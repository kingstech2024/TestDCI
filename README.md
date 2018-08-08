##Test Delegated Certificate Installer (Test DCI)
The Test Delegated Certificate Installer (Test DCI) app is intended to illustrate usage of the [key generation features](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#generateKeyPair(android.content.ComponentName,%20java.lang.String,%20android.security.keystore.KeyGenParameterSpec,%20int) available since Android P. Apps using these interfaces are required to be designated as device owner, profile owner, device owner delegate or profile owner delegate. Test DCI is intended as a companion to [Test DPC](https://github.com/googlesamples/android-testdpc), which can be used to designate TestDCI as a delegated certificate installer within a work profile. 

TestDCI features five buttons. The "Determine Situation" button must be clicked first, to allow the app to try and determine how (or if) it has been situated relative to using the key generation APIs. Device owners and profile owners pass non-NULL componentName parameters to generateKeyPair, delegates pass NULL. Device owners and device owner delegates may request attestations with device identifiers, profile owners and delegates may not. Support for hardware attestations is detected as well, with software attestations basically ignored (owing to Purebred heritage).

The "Generate Key" button generates a key with alias "TestDciExampleKey". The generateKey API is exercised per the classification performed by "Determine Situation". If generation is successful, the attestation record is saved to the Downloads folder to facilitate exporting for off-device analysis.

The "Save Certification Path" button may be used to export the certificate chain associated with the "TestDciExampleKey" alias. The chain is saved to the Downloads folder to facilitate off-device analysis. The chain value changes following installation of a CA-signed key, giving three views of the public key: attestation record, certificate chain available prior to installation of a CA-signed certificate and certificate chain available after installation of a CA-signed certificate.

The "Install CA-signed Certificate" button may be used to generate a certificate signed using the Good CA from [NIST's PKI test suite](https://csrc.nist.gov/Projects/PKI-Testing) (PKITS). The certificate is installed using the setKeyPairCertificate API and may be saved to the Downloads folder using the "Save Certification Path" button.

The "Delete Key" button deletes the "TestDciExampleKey" alias.

The requested permissions are required to save the attestation record and certification paths to easily accessibly locations to facilitate review of the artifacts.

To test as a profile owner delegate, install the TestDPC app and create a new work container. Install the TestDCI app in the work container and use TestDPC to designated TestDCI as a delegated certificate installer. 

To test as a device owner, install TestDCI and use adb to mark it as a device owner as follows:

	adb shell dpm set-device-owner androidtestdci.hound.red.testdci/.TestDciReceiver

Testing has not been performed for device owner delegate or profile owner scenarios. 




