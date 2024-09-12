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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"math/big"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	certsv1 "github.com/buraksekili/certificate-operator/api/v1"
)

const (
	defaultKeySize = 2048
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("Certificate", req.NamespacedName)

	var desired certsv1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &desired); err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Return and don't requeue
			l.Info("Certificate resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}

		// Error reading the object - requeue the request.
		l.Error(err, "Failed to get Certificate")
		return ctrl.Result{}, err
	}

	// TODO: finalizer

	// Check if we need to create or update the secret
	secret := &corev1.Secret{}

	err := r.Get(ctx, types.NamespacedName{Name: desired.Spec.SecretRef.Name, Namespace: desired.Namespace}, secret)
	if errors.IsNotFound(err) {
		l.Info("Creating a new Secret", "Secret.Namespace", desired.Namespace, "Secret.Name", desired.Spec.SecretRef.Name)
		secret, err = r.createSecret(ctx, l, &desired)
		if err != nil {
			l.Error(err, "Failed to create new Secret", "Secret.Namespace", desired.Namespace, "Secret.Name", desired.Spec.SecretRef.Name)
			return ctrl.Result{}, err
		}
	} else if err != nil {
		l.Error(err, "Failed to get Secret")
		return ctrl.Result{}, err
	}

	// Secret exists, check if it needs to be updated
	if r.shouldUpdateSecret(&desired, secret) {
		l.Info("Updating existing Secret", "Secret.Namespace", desired.Namespace, "Secret.Name", desired.Spec.SecretRef.Name)

		if err = r.renewCertificate(ctx, &desired, secret); err != nil {
			l.Error(err, "Failed to update Secret", "Secret.Namespace", desired.Namespace, "Secret.Name", desired.Spec.SecretRef.Name)
			return ctrl.Result{}, err
		}
	}

	// Update the certificate status
	if err = r.updateCertificateStatus(ctx, &desired, secret); err != nil {
		l.Error(err, "Failed to update Certificate status")
		return ctrl.Result{}, err
	}

	l.Info("Successfully reconciled")
	return ctrl.Result{RequeueAfter: r.calculateNextReconcile(&desired)}, nil
}

func (r *CertificateReconciler) calculateNextReconcile(cert *certsv1.Certificate) time.Duration {
	// Schedule next reconcile at 2/3 of the way to expiry
	return cert.Status.NotAfter.Sub(cert.Status.NotBefore.Time) / 3
}

func (r *CertificateReconciler) shouldUpdateSecret(cert *certsv1.Certificate, secret *corev1.Secret) bool {
	certPEM, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return true
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}

	// Check if DNS name has changed
	if x509Cert.Subject.CommonName != cert.Spec.DNSName {
		return true
	}

	// Check if the certificate is nearing expiration
	// We'll use 2/3 of the desired validity period as the renewal threshold
	desiredValidity := cert.Spec.Validity.Duration
	renewalThreshold := time.Now().Add(desiredValidity * 2 / 3)

	return x509Cert.NotAfter.Before(renewalThreshold)
}

func (r *CertificateReconciler) renewCertificate(ctx context.Context, cert *certsv1.Certificate, secret *corev1.Secret) error {
	// Generate new certificate and key
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	template, err := r.createCertificateTemplate(cert)
	if err != nil {
		return fmt.Errorf("failed to create certificate template: %v", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode the new private key and certificate
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// Update the Secret
	secret.Data[corev1.TLSCertKey] = certPEM
	secret.Data[corev1.TLSPrivateKeyKey] = privKeyPEM

	if err = r.Update(ctx, secret); err != nil {
		return fmt.Errorf("failed to update Secret: %v", err)
	}

	return nil
}

func (r *CertificateReconciler) createSecret(ctx context.Context, log logr.Logger, cert *certsv1.Certificate) (*corev1.Secret, error) {
	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create a certificate template
	template, err := r.createCertificateTemplate(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate template: %v", err)
	}

	// Create a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode the private key and certificate to PEM format
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// Create the Secret object
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert.Spec.SecretRef.Name,
			Namespace: cert.Namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: privKeyPEM,
		},
	}

	// Set the Certificate as the owner of the Secret
	if err = controllerutil.SetControllerReference(cert, secret, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set owner reference: %v", err)
	}

	// Create the Secret in the cluster
	if err = r.Create(ctx, secret); err != nil {
		return nil, fmt.Errorf("failed to create Secret: %v", err)
	}

	log.Info("Created new Secret for Certificate", "Secret.Name", secret.Name)
	return secret, nil
}

func (r *CertificateReconciler) createCertificateTemplate(cert *certsv1.Certificate) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(cert.Spec.Validity.Duration)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cert.Spec.DNSName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cert.Spec.DNSName},
	}

	return &template, nil
}

func (r *CertificateReconciler) updateCertificateStatus(ctx context.Context, cert *certsv1.Certificate, secret *corev1.Secret) error {
	certPEM := secret.Data[corev1.TLSCertKey]
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	cert.Status.NotBefore = metav1.NewTime(x509Cert.NotBefore)
	cert.Status.NotAfter = metav1.NewTime(x509Cert.NotAfter)
	cert.Status.SerialNumber = x509Cert.SerialNumber.String()
	cert.Status.Issuer = x509Cert.Issuer.CommonName
	cert.Status.LastRenewalTime = metav1.NewTime(time.Now())

	// Update the Ready condition
	readyCondition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "CertificateIssued",
		Message:            "Certificate has been issued successfully",
		LastTransitionTime: metav1.NewTime(time.Now()),
	}

	// Update the Conditions array
	if len(cert.Status.Conditions) == 0 {
		cert.Status.Conditions = []metav1.Condition{readyCondition}
	} else {
		meta.SetStatusCondition(&cert.Status.Conditions, readyCondition)
	}

	return r.Status().Update(ctx, cert)
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certsv1.Certificate{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
