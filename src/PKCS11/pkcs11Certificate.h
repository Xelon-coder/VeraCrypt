#ifndef PKCS11_CERTIFICATE
#define PKCS11_CERTIFICATE

#include <pkcs11.h>
#include "Platform/Exception.h"
#include <iostream>

namespace VeraCrypt {

    #ifndef SECURITY_CERTIFICATE_INFO
    #define SECURITY_CERTIFICATE_INFO

    struct SecurityCertificateInfo
    {
        CK_OBJECT_HANDLE cert;
        string label;
    };

    #endif

    class pkcs11Certificate {
            
        public:

            SecurityCertificateInfo const GetCertificateInfo(CK_SLOT_ID slotId, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE attributeType);
            vector <SecurityCertificateInfo> const GetAvailableCertificate();

            void Encrypt();
            void Decrypt();
    };
}

#endif