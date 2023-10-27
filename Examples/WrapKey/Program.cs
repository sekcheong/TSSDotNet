using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Tpm2Lib;

namespace WrapKey
{
    class Program
    {
        /// <summary>
        /// Creates a primary RSA storage key in the storage hierarchy and returns its
        /// handle. The caller can provide an auth value and additional entropy for
        /// the key derivation (primary keys are deterministically derived by the TPM
        /// from an internal primary seed value unique for each hierarchy).
        /// The caller is responsible for disposing of the returned key handle.
        /// </summary>
        /// <param name="auth">Optional auth value to be associated with the created key.</param>
        /// <param name="seed">Optional entropy that may be used to create different primary keys with exactly the same template.</param>
        /// <returns></returns>
        static TpmHandle CreateRsaPrimaryStorageKey(Tpm2 tpm, byte[] auth = null, byte[] seed = null)
        {
            TpmPublic newKeyPub;
            return CreateRsaPrimaryStorageKey(tpm, out newKeyPub, seed, auth);
        }

        /// <summary>
        /// Creates a primary RSA storage key in the storage hierarchy and returns its
        /// handle and public area. The caller can provide an auth value and additional
        /// entropy for the key derivation (primary keys are deterministically derived
        /// by the TPM from an internal primary seed value unique for each hierarchy).
        /// The caller is responsible for disposing of the returned key handle.
        /// </summary>
        /// <param name="newKeyPub">Public area of the created key. Its 'unique' member contains the actual public key of the generated key pair.</param>
        /// <param name="auth">Optional auth value to be associated with the created key.</param>
        /// <param name="seed">Optional entropy that may be used to create different primary keys with exactly the same template.</param>
        /// <returns></returns>
        static TpmHandle CreateRsaPrimaryStorageKey(Tpm2 tpm, out TpmPublic newKeyPub, byte[] auth = null, byte[] seed = null)
        {
            // auth data provided by caller, no private key bits for asymmetric keys
            var sensCreate = new SensitiveCreate(auth, null);

            // Typical storage key template
            var parms = new TpmPublic(
                TpmAlgId.Sha256,                                 
                ObjectAttr.Restricted | ObjectAttr.Decrypt |      // Storage key
                ObjectAttr.FixedParent | ObjectAttr.FixedTPM |    // Non-duplicable
                ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
                null,                                             
                new RsaParms(new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb), null, 2048, 0),
                new Tpm2bPublicKeyRsa(seed)    
            );

            CreationData creationData;
            TkCreation creationTicket;
            byte[] creationHash;

            return tpm.CreatePrimary(
                TpmRh.Owner,          
                sensCreate,                                                
                parms,    
                null,         
                new PcrSelection[0],  // Not PCR-bound
                out newKeyPub,        // Our outs
                out creationData, out creationHash, out creationTicket);
        } 

        static byte[] Encrypt(Tpm2 tpm, TpmPublic keyPub, TpmHandle hParent, byte[] message, out byte[] iv)
        {
            var keyAuth = AuthValue.FromString(TpmAlgId.Sha256, "lotsofcats");         
            var key = TssObject.Create(keyPub, keyAuth);

            iv = null;
            return null;
        }

        static byte[] Decrypt(Tpm2 tpm, TpmPublic keyPub, TpmHandle hParent, byte[] cipher, byte[] iv)
        {
            return null;
        }

        static void Main(string[] args)
        {
            // Connect to the simulator on this machine    
            var device = new TbsDevice();
            device.Connect();
            Tpm2 tpm = new Tpm2(device);

            var hPrim = CreateRsaPrimaryStorageKey(tpm);

            var keyPub = new TpmPublic(
                        TpmAlgId.Sha256,
                        ObjectAttr.Decrypt | ObjectAttr.UserWithAuth,
                        null,
                        new SymDefObject(TpmAlgId.Aes, 256, TpmAlgId.Cfb),
                        new Tpm2bDigestSymcipher()
                        );

            var keyAuth = AuthValue.FromString(TpmAlgId.Sha256, "lotsofcats");

            // Generate the key
            TssObject swKey = TssObject.Create(keyPub, keyAuth);



            tpm.Dispose();
        }
    }
}
