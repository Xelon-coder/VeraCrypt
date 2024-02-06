#include "pkcs11Certificate.h"
#include "SecurityToken.h"

namespace VeraCrypt {

    SecurityCertificateInfo const pkcs11Certificate::GetCertificateInfo(CK_SLOT_ID slotId, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE attributeType){
        
        SecurityCertificateInfo certificate;
        certificate.cert = object;

        vector <byte> attributeValue;

        SecurityToken::GetObjectAttribute(slotId,object,attributeType,attributeValue);

		certificate.label = string(reinterpret_cast<const char*>(&attributeValue[0]),attributeValue.size());

		std::cout << certificate.label << std::endl;

        return certificate;
        
    }

    vector <SecurityCertificateInfo> const pkcs11Certificate::GetAvailableCertificate(){
        
        vector <SecurityCertificateInfo> certificates;
        CK_ATTRIBUTE_TYPE objectClass = CKO_PUBLIC_KEY;

        CK_SLOT_ID slotId = SecurityToken::GetTokenSlots().front();
        
        vector <CK_OBJECT_HANDLE> certificatesHandle = SecurityToken::GetObjects(slotId,objectClass);

        for(CK_OBJECT_HANDLE cert: certificatesHandle) {
            
            try {

                certificates.push_back(GetCertificateInfo(slotId,cert,CKA_LABEL));

            } catch (Pkcs11Exception& e){
                
                std::cout << e.GetSubject().c_str() << std::endl;  // Debug

                throw Pkcs11Exception(e);
            }

        }

        return certificates;

    }

}