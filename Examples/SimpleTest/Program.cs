using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Tpm2Lib;

namespace SimpleTest
{
    class Program
    {
        static void Main(string[] args)
        {
            // Connect to the simulator on this machine    
            var device = new TbsDevice();
            device.Connect();
            Tpm2 tpm = new Tpm2(device);

            // Ask the TPM for some random data
            byte[] rand = tpm.GetRandom(16);
       
            Console.Write("Random data:" + BitConverter.ToString(rand));

            // And close the connection to the TPM
            tpm.Dispose();

        }
    }
}
