using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Tpm2Lib;

namespace WrapKey
{
    class Program
    {
   

        static byte[] GetKeyFromTPM()
        {
            Tpm2Device tpmDevice;

            tpmDevice = new TbsDevice();

            tpmDevice.Connect();

            //
            // Pass the device object used for communication to the TPM 2.0 object
            // which provides the command interface.
            var tpm = new Tpm2(tpmDevice);

            // AuthValue encapsulates an authorization value: essentially a byte-array.
            // OwnerAuth is the owner authorization value of the TPM-under-test.  We
            // assume that it (and other) auths are set to the default (null) value.
            // If running on a real TPM, which has been provisioned by Windows, this
            // value will be different. An administrator can retrieve the owner
            var ownerAuth = new AuthValue();

            // The TPM needs a template that describes the parameters of the key
            // or other object to be created.  The template below instructs the TPM 
            // to create a new 2048-bit non-migratable signing key.
            var keyTemplate = new TpmPublic(TpmAlgId.Sha1,                                  // Name algorithm
                                            ObjectAttr.UserWithAuth | ObjectAttr.Sign | ObjectAttr.Encrypt |    // Signing key
                                            ObjectAttr.FixedParent | ObjectAttr.FixedTPM | // Non-migratable 
                                            ObjectAttr.SensitiveDataOrigin,
                                            null,                                    // No policy
                                            new RsaParms(new SymDefObject(),
                                                         new SchemeRsassa(TpmAlgId.Sha1), 1024, 0),
                                            new Tpm2bPublicKeyRsa());

            // 
            // Authorization for the key we are about to create.
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
            return signature.sig;
        }

        static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        static void Main(string[] args)
        {
            var key = GetKeyFromTPM();

            byte[] aeskey = new byte[32];
            Array.Copy(key, aeskey, 32);
            var txt = Convert.ToBase64String(aeskey, 0, aeskey.Length);
            Console.WriteLine("Key:" + txt);

            //string ivstr = "7E892875A52C59A3B588306B13C31FBD";
            byte[] iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

            string original = "Here is some data to encrypt!";

            // Encrypt the string to an array of bytes.
            byte[] encrypted = EncryptStringToBytes(original, aeskey, iv);

            // Decrypt the bytes to a string.
            string roundtrip = DecryptStringFromBytes(encrypted, aeskey, iv);

            //Display the original data and the decrypted data.
            Console.WriteLine("Original:   {0}", original);
            Console.WriteLine("Round Trip: {0}", roundtrip);

        }
    }
}
