/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"k8s.io/apimachinery/pkg/api/errors"
	"time"

	certsv1 "github.com/buraksekili/certificate-operator/api/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

func deleteAndWait(ctx context.Context, obj client.Object, key types.NamespacedName) {
	err := k8sClient.Delete(ctx, obj)
	ExpectWithOffset(1, err).To(SatisfyAny(BeNil(), Satisfy(errors.IsNotFound)))

	Eventually(func() error {
		return k8sClient.Get(ctx, key, obj)
	}, timeout, interval).Should(Satisfy(errors.IsNotFound))
}

var _ = Describe("Certificate Controller", func() {
	const (
		CertificateName      = "test-cert"
		CertificateNamespace = "default"
		DNSName              = "example.com"
		SecretName           = "test-cert-secret"
	)

	ctx := context.Background()

	AfterEach(func() {
		ctx := context.Background()

		deleteAndWait(ctx, &certsv1.Certificate{ObjectMeta: metav1.ObjectMeta{Name: CertificateName, Namespace: CertificateNamespace}},
			types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace})

		deleteAndWait(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: SecretName, Namespace: CertificateNamespace}},
			types.NamespacedName{Name: SecretName, Namespace: CertificateNamespace})
	})

	It("should create a new Secret when a Certificate is created", func() {
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: CertificateName, Namespace: CertificateNamespace},
			Spec: certsv1.CertificateSpec{
				DNSName:   DNSName,
				Validity:  metav1.Duration{Duration: 24 * time.Hour},
				SecretRef: certsv1.SecretReference{Name: SecretName},
			},
		}

		Expect(k8sClient.Create(ctx, cert)).To(Succeed())

		createdCert := &certsv1.Certificate{}
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}, createdCert)
		}, timeout, interval).Should(Succeed())

		var secret corev1.Secret
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Name: SecretName, Namespace: CertificateNamespace}, &secret)
		}, timeout, interval).Should(Succeed())

		Expect(secret.Data).To(HaveKey(corev1.TLSCertKey))
		Expect(secret.Data).To(HaveKey(corev1.TLSPrivateKeyKey))

		// Verify certificate contents
		block, _ := pem.Decode(secret.Data[corev1.TLSCertKey])
		Expect(block).NotTo(BeNil())

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(x509Cert.Subject.CommonName).To(Equal(DNSName))
	})

	It("should update the certificate when the DNS name is changed", func() {
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: CertificateName, Namespace: CertificateNamespace},
			Spec: certsv1.CertificateSpec{
				DNSName:   DNSName,
				Validity:  metav1.Duration{Duration: 24 * time.Hour},
				SecretRef: certsv1.SecretReference{Name: SecretName},
			},
		}
		Expect(k8sClient.Create(ctx, cert)).To(Succeed())

		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Name: SecretName, Namespace: CertificateNamespace}, &corev1.Secret{})
		}, timeout, interval).Should(Succeed())

		updatedDNSName := "newexample.com"
		Eventually(func() error {
			var certToUpdate certsv1.Certificate
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}, &certToUpdate); err != nil {
				return err
			}
			certToUpdate.Spec.DNSName = updatedDNSName
			return k8sClient.Update(ctx, &certToUpdate)
		}, timeout, interval).Should(Succeed())

		var secret corev1.Secret
		Eventually(func() string {
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: SecretName, Namespace: CertificateNamespace}, &secret)).To(Succeed())
			block, _ := pem.Decode(secret.Data[corev1.TLSCertKey])
			if block == nil {
				return ""
			}
			x509Cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return ""
			}
			return x509Cert.Subject.CommonName
		}, timeout, interval).Should(Equal(updatedDNSName))
	})

	It("should renew the certificate when approaching expiration", func() {
		shortValidity := 12 * time.Second
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: CertificateName, Namespace: CertificateNamespace},
			Spec: certsv1.CertificateSpec{
				DNSName:   DNSName,
				Validity:  metav1.Duration{Duration: shortValidity},
				SecretRef: certsv1.SecretReference{Name: SecretName},
			},
		}

		Expect(k8sClient.Create(ctx, cert)).To(Succeed())

		var initialSecret corev1.Secret
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Name: SecretName, Namespace: CertificateNamespace}, &initialSecret)
		}, timeout, interval).Should(Succeed())

		initialCert := parseCertFromSecret(&initialSecret)
		initialExpiryTime := initialCert.NotAfter

		// Wait for the certificate to approach expiration
		time.Sleep(shortValidity * 2 / 3)

		Eventually(func() time.Time {
			var renewedSecret corev1.Secret
			err := k8sClient.Get(ctx, types.NamespacedName{Name: SecretName, Namespace: CertificateNamespace}, &renewedSecret)
			Expect(err).NotTo(HaveOccurred())

			renewedCert := parseCertFromSecret(&renewedSecret)
			return renewedCert.NotAfter
		}, timeout, interval).Should(BeTemporally(">", initialExpiryTime))
	})

	It("should update the Certificate status correctly", func() {
		cert := &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: CertificateName, Namespace: CertificateNamespace},
			Spec: certsv1.CertificateSpec{
				DNSName:   DNSName,
				Validity:  metav1.Duration{Duration: 24 * time.Hour},
				SecretRef: certsv1.SecretReference{Name: SecretName},
			},
		}

		Expect(k8sClient.Create(ctx, cert)).To(Succeed())

		Eventually(func() bool {
			var updatedCert certsv1.Certificate
			err := k8sClient.Get(ctx, types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}, &updatedCert)
			if err != nil {
				return false
			}

			status := updatedCert.Status

			if status.SerialNumber == "" || status.Issuer == "" {
				return false
			}

			if len(status.Conditions) != 1 {
				return false
			}

			condition := status.Conditions[0]
			return condition.Type == "Ready" && condition.Status == metav1.ConditionTrue
		}, timeout, interval).Should(BeTrue())

		var finalCert certsv1.Certificate
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}, &finalCert)).To(Succeed())

		Expect(finalCert.Status.NotBefore).NotTo(BeNil())
		Expect(finalCert.Status.NotAfter).NotTo(BeNil())
		Expect(finalCert.Status.SerialNumber).NotTo(BeEmpty())
		Expect(finalCert.Status.Issuer).NotTo(BeEmpty())
		Expect(finalCert.Status.LastRenewalTime).NotTo(BeNil())
		Expect(finalCert.Status.Conditions).To(HaveLen(1))
		Expect(finalCert.Status.Conditions[0].Type).To(Equal("Ready"))
		Expect(finalCert.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
	})
})

func parseCertFromSecret(secret *corev1.Secret) *x509.Certificate {
	block, _ := pem.Decode(secret.Data[corev1.TLSCertKey])
	Expect(block).NotTo(BeNil())

	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())

	return cert
}
