using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSAEncryption
{
    public class RSAEncryption
    {
        static public byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider. 
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048))
                {
                    
                    //my pub key
                    RSA.FromXmlString("<RSAKeyValue><Modulus>vEZ60y9YT1dNZpE2DQ/gQ0X8XC6louyB2DC6qCLFQegXbzYyEvFsfBu5QLC7mei+EfT62UcJn4b15r+IM7aGSi/r4rrwMoJFcJACeNkYGWrg4rUaMNJjWhCSsl9hy8gACS4QXQuwJBq1wTLrdZDTogpxzy5ntsGZx8tEXNPCcnC+cvGcbrmRfev9RMuJr/PX5XQDOFq/+e6NO8DxtZnpWKomMArXsUgZhJ8vUDSrMq3c89q28dVVoxhxSycAEptomV37k0e5xgLxR8xNYqmpuuH0EiHAuY3kcLKcu5WcBSxnUmN7qj55iw7yGyHKyXKLZiFKRqoZV+qGztkqs9MJQw==</Modulus><Exponent>AQAB</Exponent><P>3XGs+bKjFRBs+bC8PVqlJ7q7iYATYxAeSlgXHN5aEvBiyw3y0nUFuSTfW+JWW6QH3MS+ztDHru2trf+6yQkzKJ0IpOFomqeRkjxo3U0aTavMJ3aZKCJwCf7F1UP3dTGhrnYg3M3s07PwFYS63DW6oNAkE028pH2+MbB4aKW17h8=</P><Q>2afElLskNxHBvZUZfXVa1CVfgZMQEL/yL7IS+I3SEZFy6vQBxtnGvy+o66hhJgVb2kQlWFB+4ohoovJWU26tMdpL+hes+KEnumg74MVTtx4p0cPt8RP+igkF1/HPnsS1ltr40wDEWDj6UKcTM1WiKj9ZdqQekhArDLL6STlDeF0=</Q><DP>IrRxFoUPl/qGCa/QIJF3Nr3GLGt9HlZlWONrY+PZHAS+hvI9rwwWBIkp1D2pqR0Q+mF/QexojxrC0HU2sdEWSnQp6aVF/o7qeo+rI5u01p1pFno40JhtFLPwD1dijeRkYXIz/kbrqdYWd1jg7CgjgpZ8QOY6/VCToTf19viZhaM=</DP><DQ>C8vr+6Oo8tMjjQLnvsT9h0H/SyaNWFsO5UbhgFcva4RWliVjc0OaYgJTRXJ60XS45buLyp2SQvThtvMrepolCO6r74IY/eC+Jnw/wo7vWp1n5taXrtlGknSqvGl+tzwyG1sC4WzJN37fEj/76mxZvbBxSNzcS05VBvssVYuk/IE=</DQ><InverseQ>3S5gpZu2K0RoIYCk4K+t8BYEdFqaJgkXS7BEW7bVOxzD9w/8b8DqpU2wZ3fyapNio16mUBVmTnDPOy6Jv3bMyele5OJD8PryulwLSp2VUUyVPghtoxJQjJ43O92wX1i8wrQVdFqM3gwGhKH6f9ClZjC4FXELNb+5iZagnfMwEeo=</InverseQ><D>PdByERYxS1NhgTRZ5633tn6q3WUfUr+N3foZvowz8XCPCR9lD10efhzoFLoxzdVhWinxlhbBrRO1dn4Z7MiXjJHxQ26W4C5vOAbAGQdF50p07VoCcFcS8YYRc+jnBe3zPRBXpQTqXuA6HmVmcyIKqd/9/8S/nnwvzi4JkuSfqcyUQClP77WbWgRpj80Kj/LToRnV1vox0mksKhLa3mzgvJvg/PCmqNToVg6fJ/LxCTdD/cHX8+R7uj9BeZ47LRkPCdPDCIlAo8/i8wJRBkme3M7Ne642I1HLp7VynJ7zgtMtJ/kfqkTZX/ulyfzWtAqWLJv00KNgSGxlZ4WsVE3kKQ==</D></RSAKeyValue>");


                    //Import the RSA Key information. This only needs 
                    //toinclude the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.   
                    //OAEP padding is only available on Microsoft Windows XP or 
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException   
            //to the console. 
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }

        }

        static public byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider. 
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048))
                {
                    //my pub key
                    RSA.FromXmlString("<RSAKeyValue><Modulus>vEZ60y9YT1dNZpE2DQ/gQ0X8XC6louyB2DC6qCLFQegXbzYyEvFsfBu5QLC7mei+EfT62UcJn4b15r+IM7aGSi/r4rrwMoJFcJACeNkYGWrg4rUaMNJjWhCSsl9hy8gACS4QXQuwJBq1wTLrdZDTogpxzy5ntsGZx8tEXNPCcnC+cvGcbrmRfev9RMuJr/PX5XQDOFq/+e6NO8DxtZnpWKomMArXsUgZhJ8vUDSrMq3c89q28dVVoxhxSycAEptomV37k0e5xgLxR8xNYqmpuuH0EiHAuY3kcLKcu5WcBSxnUmN7qj55iw7yGyHKyXKLZiFKRqoZV+qGztkqs9MJQw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>");


                    //Import the RSA Key information. This needs 
                    //to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding.   
                    //OAEP padding is only available on Microsoft Windows XP or 
                    //later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException   
            //to the console. 
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }

        }
    }
}
