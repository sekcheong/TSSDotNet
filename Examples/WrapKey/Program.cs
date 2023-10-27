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


        static byte[] GetKeyFromTPM()
        {
            Tpm2Device tpmDevice;

            tpmDevice = new TbsDevice();

            tpmDevice.Connect();

            //
            // Pass the device object used for communication to the TPM 2.0 object
            // which provides the command interface.
            // 
            var tpm = new Tpm2(tpmDevice);


            //
            // AuthValue encapsulates an authorization value: essentially a byte-array.
            // OwnerAuth is the owner authorization value of the TPM-under-test.  We
            // assume that it (and other) auths are set to the default (null) value.
            // If running on a real TPM, which has been provisioned by Windows, this
            // value will be different. An administrator can retrieve the owner
            // authorization value from the registry.
            //
            var ownerAuth = new AuthValue();

            // 
            // The TPM needs a template that describes the parameters of the key
            // or other object to be created.  The template below instructs the TPM 
            // to create a new 2048-bit non-migratable signing key.
            // 
            var keyTemplate = new TpmPublic(TpmAlgId.Sha1,                                  // Name algorithm
                                            ObjectAttr.UserWithAuth | ObjectAttr.Sign | ObjectAttr.Encrypt |    // Signing key
                                            ObjectAttr.FixedParent | ObjectAttr.FixedTPM | // Non-migratable 
                                            ObjectAttr.SensitiveDataOrigin,
                                            null,                                    // No policy
                                            new RsaParms(new SymDefObject(),
                                                         new SchemeRsassa(TpmAlgId.Sha1), 2048, 0),
                                            new Tpm2bPublicKeyRsa());

            // 
            // Authorization for the key we are about to create.
            // 
            var keyAuth = new byte[] { 1, 2, 3 };

            TpmPublic keyPublic;
            CreationData creationData;
            TkCreation creationTicket;
            byte[] creationHash;

            // 
            // Ask the TPM to create a new primary RSA signing key.
            // 
            TpmHandle keyHandle = tpm[ownerAuth].CreatePrimary(
                TpmRh.Owner,                            // In the owner-hierarchy
                new SensitiveCreate(keyAuth, null),     // With this auth-value
                keyTemplate,                            // Describes key
                null,                                   // Extra data for creation ticket
                new PcrSelection[0],                    // Non-PCR-bound
                out keyPublic,                          // PubKey and attributes
                out creationData, out creationHash, out creationTicket);    // Not used here

            // 
            // Print out text-versions of the public key just created
            // 
            Console.WriteLine("New public key\n" + keyPublic.ToString());

            // 
            // Use the key to sign some data
            // 
            byte[] message = Encoding.Unicode.GetBytes("ABC");
            TpmHash digestToSign = TpmHash.FromData(TpmAlgId.Sha1, message);

            // 
            // A different structure is returned for each signing scheme, 
            // so cast the interface to our signature type (see third argument).
            // 
            // As an alternative, 'signature' can be of type ISignatureUnion and
            // cast to SignatureRssa whenever a signature specific type is needed.
            // 
            var signature = tpm[keyAuth].Sign(keyHandle,            // Handle of signing key
                                              digestToSign,         // Data to sign
                                              null,                 // Use key's scheme
                                             TpmHashCheck.Null()) as SignatureRsassa;
            // 
            // Print the signature.
            // 
            Console.WriteLine("Signature: " + BitConverter.ToString(signature.sig));

            return signature.sig;
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
            var k = GetKeyFromTPM();
            var txt = Convert.ToBase64String(k,0,k.Length);
            Console.WriteLine(txt);
        }
    }
}
