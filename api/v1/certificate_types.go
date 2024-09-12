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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CertificateSpec defines the desired state of Certificate
type CertificateSpec struct {
	// DNSName is the DNS name for which the certificate should be issued
	DNSName string `json:"dnsName"`

	// Validity is the time until the certificate expires
	Validity metav1.Duration `json:"validity"`

	// SecretRef is a reference to the Secret object in which the certificate is stored
	SecretRef SecretReference `json:"secretRef"`
}

// SecretReference contains the name of the secret
type SecretReference struct {
	// Name is the name of the secret
	Name string `json:"name"`
}

// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct {
	// Conditions represent the latest available observations of an object's state
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// NotBefore is the time at which the certificate becomes valid
	NotBefore metav1.Time `json:"notBefore,omitempty"`

	// NotAfter is the time at which the certificate becomes invalid
	NotAfter metav1.Time `json:"notAfter,omitempty"`

	// SerialNumber is the serial number of the certificate
	SerialNumber string `json:"serialNumber,omitempty"`

	// Issuer is the issuer of the certificate
	Issuer string `json:"issuer,omitempty"`

	// LastRenewalTime is the time at which the certificate was last renewed
	LastRenewalTime metav1.Time `json:"lastRenewalTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName="c"

// Certificate is the Schema for the certificates API
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSpec   `json:"spec,omitempty"`
	Status CertificateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CertificateList contains a list of Certificate
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Certificate{}, &CertificateList{})
}
