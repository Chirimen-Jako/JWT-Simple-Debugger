using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace JWT_Debugger
{
    public struct JsonData
    {
        public (string key, string value)[] pair;
    }

    internal static class StringHelper
    {
        public static string FirstSegment(this string input, char separator)
        {
            var idx = input.IndexOf(separator);
            return idx != -1 ? input.Substring(0, idx) : input;
        }
    }

    class Program
    {
        private static readonly UTF8Encoding _utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        public static byte[] GetBytes(string input) =>
            _utf8Encoding.GetBytes(input);

        internal static string ReadText(string filename)
        {
            string text = File.ReadAllText(filename);
            text = text.Replace(" ", "");
            return text.Replace(Environment.NewLine, "");
        }

        internal static string ReadKeyText(string filename)
        {
            string text = File.ReadAllText(filename);
            text = Regex.Replace(text, "-+(BEGIN|END) .*(PUBLIC|PRIVATE) KEY-+", "");
            text = text.Replace(" ", "");
            return text.Replace(Environment.NewLine, "");
        }

        internal static string Base64UrlEncode(byte[] inputBytes)
        {
            string output = Convert.ToBase64String(inputBytes);
            output = output.FirstSegment('='); // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        internal static string Base64UrlEncode(string inputText)
        {
            return Base64UrlEncode(GetBytes(inputText));
        }

        internal static RSA CreateRSAPublicKey(string publicKey)
        {
            RSA rsaPublic = RSA.Create();
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            rsaPublic.ImportSubjectPublicKeyInfo(publicKeyBytes, out int _);
            return rsaPublic;
        }

        internal static RSA CreateRSAPrivateKey(string privateKey)
        {
            RSA rsaPrivate = RSA.Create();
            byte[] privateKeyBytes = Convert.FromBase64String(privateKey);
            rsaPrivate.ImportPkcs8PrivateKey(privateKeyBytes, out int _);
            return rsaPrivate;
        }

        internal static string Encode(string header, string payload, string publicKey, string privateKey)
        {
            RSA rsaPrivate = CreateRSAPrivateKey(privateKey);

            var headerSegment = Base64UrlEncode(header);
            var payloadSegment = Base64UrlEncode(payload);

            var stringToSign = headerSegment + "." + payloadSegment;
            var bytesToSign = GetBytes(stringToSign);

            byte[] signature = rsaPrivate.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            RSA rsaPublic = CreateRSAPublicKey(publicKey);

            bool verified = rsaPublic.VerifyData(bytesToSign, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (verified)
            {
                Console.Error.WriteLine("Validation Succeeded.");
            }
            else
            {
                Console.Error.WriteLine("Validation Failed.");
            }

            string token = stringToSign + "." + Base64UrlEncode(signature);

            return token;
        }

        static void Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    Console.WriteLine("Usage:");
                    Console.WriteLine("JWTTest <header file path> <payload file path> <public key file path> <private key file path>");
                    Environment.Exit(0);
                }

                string headerFile = args[0];
                string payloadFile = args[1];
                string publicKeyFile = args[2];
                string privateKeyFile = args[3];

                string header = ReadText(headerFile);
                string payload = ReadText(payloadFile);
                string publicKey = ReadKeyText(publicKeyFile);
                string privateKey = ReadKeyText(privateKeyFile);

                try
                {
                    JsonData objHeader = JsonSerializer.Deserialize<JsonData>(header);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("header is INVALID json structure.");
                    throw ex;
                }
                try
                {
                    JsonData objPayload = JsonSerializer.Deserialize<JsonData>(payload);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("payload is INVALID json structure.");
                    throw ex;
                }

                var token = Encode(header, payload, publicKey, privateKey);

                Console.WriteLine(token);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                Environment.Exit(69);
            }
        }
    }
}
