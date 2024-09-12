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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	certsv1 "github.com/buraksekili/certificate-operator/api/v1"
)

var _ = Describe("Certificate Controller", func() {
	const (
		CertificateName      = "test-cert"
		CertificateNamespace = "default"
		DNSName              = "example.com"
		SecretName           = "test-cert-secret"
	)

	ctx := context.Background()
	var reconciler *CertificateReconciler

	BeforeEach(func() {
		reconciler = &CertificateReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	})

	AfterEach(func() {
		err := k8sClient.Delete(ctx, &certsv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: CertificateName, Namespace: CertificateNamespace},
		})
		Expect(err).To(SatisfyAny(BeNil(), Satisfy(errors.IsNotFound)))

		err = k8sClient.Delete(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: SecretName, Namespace: CertificateNamespace},
		})
		Expect(err).To(SatisfyAny(BeNil(), Satisfy(errors.IsNotFound)))
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

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}})
		Expect(err).NotTo(HaveOccurred())

		secret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: SecretName, Namespace: CertificateNamespace}, secret)).To(Succeed())

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

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}})
		Expect(err).NotTo(HaveOccurred())

		newCertToUpdate := certsv1.Certificate{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}, &newCertToUpdate)).To(Succeed())

		updatedDNSName := "newexample.com"
		newCertToUpdate.Spec.DNSName = updatedDNSName
		Expect(k8sClient.Update(ctx, &newCertToUpdate)).To(Succeed())

		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}})
		Expect(err).NotTo(HaveOccurred())

		secret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: SecretName, Namespace: CertificateNamespace}, secret)).To(Succeed())

		block, _ := pem.Decode(secret.Data[corev1.TLSCertKey])
		Expect(block).NotTo(BeNil())

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(x509Cert.Subject.CommonName).To(Equal(updatedDNSName))
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

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}})
		Expect(err).NotTo(HaveOccurred())

		// Wait for the certificate to approach expiration
		time.Sleep(shortValidity * 2 / 3)

		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}})
		Expect(err).NotTo(HaveOccurred())

		secret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: SecretName, Namespace: CertificateNamespace}, secret)).To(Succeed())

		block, _ := pem.Decode(secret.Data[corev1.TLSCertKey])
		Expect(block).NotTo(BeNil())

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(x509Cert.NotAfter).To(BeTemporally(">", time.Now().Add(shortValidity/2)))
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

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}})
		Expect(err).NotTo(HaveOccurred())

		updatedCert := &certsv1.Certificate{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}, updatedCert)).To(Succeed())

		Expect(updatedCert.Status.NotBefore).NotTo(BeNil())
		Expect(updatedCert.Status.NotAfter).NotTo(BeNil())
		Expect(updatedCert.Status.SerialNumber).NotTo(BeEmpty())
		Expect(updatedCert.Status.Issuer).NotTo(BeEmpty())
		Expect(updatedCert.Status.LastRenewalTime).NotTo(BeNil())
		Expect(updatedCert.Status.Conditions).To(HaveLen(1))
		Expect(updatedCert.Status.Conditions[0].Type).To(Equal("Ready"))
		Expect(updatedCert.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
	})
})
