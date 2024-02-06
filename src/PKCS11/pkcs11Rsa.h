#include "pkcs11Certificate.h"

namespace VeraCrypt{

    class pkcs11Rsa : public pkcs11Certificate {

        public:

            pkcs11Rsa();

        protected:

            void Encrypt();
            void Decrypt();

    };

}