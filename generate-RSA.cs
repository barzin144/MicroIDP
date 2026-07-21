using System.Security.Cryptography;
using (var rsa = RSA.Create(2048))
{
	// Export the private key
	var privateKey = rsa.ExportRSAPrivateKey();
	var privateKeyBase64 = Convert.ToBase64String(privateKey);
	Console.WriteLine("Private Key:");
	Console.WriteLine(privateKeyBase64);

	// Export the public key
	var publicKey = rsa.ExportRSAPublicKey();
	var publicKeyBase64 = Convert.ToBase64String(publicKey);
	Console.WriteLine("\nPublic Key:");
	Console.WriteLine(publicKeyBase64);
}