using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

using System.Collections;
using System.Security.Cryptography.Xml;

namespace Signature.Certificate
{
    public static class CertificateLoader
    {
        public static X509Certificate2 FromPath(string pathCert, string password)
        {
            X509Certificate2 x509Cert = new X509Certificate2(pathCert, password, X509KeyStorageFlags.MachineKeySet |
                                                                                 X509KeyStorageFlags.PersistKeySet |
                                                                                 X509KeyStorageFlags.Exportable);

            return x509Cert;
        }
        public static X509Certificate2 FromCertificateInfo(CertificateInfo ci)
        {
            return FromPath(ci.FileName, ci.Password);
        }


        public static X509Certificate2 FromXmlSigned(string xmlSigned)
        {
            XmlDocument xmlNFe = new XmlDocument();
            xmlNFe.PreserveWhitespace = true;
            xmlNFe.LoadXml(xmlSigned);

            //Carregar a assinatura
            SignedXml signedXml = new SignedXml(xmlNFe);
            XmlNodeList nodeList = xmlNFe.GetElementsByTagName("Signature");

            if (nodeList.Count == 0)
            {
                return null;
            }

            signedXml.LoadXml((XmlElement)nodeList[0]);

            //buscar o KeyInfo da assinatura
            IEnumerator keyInfoItems = signedXml.KeyInfo.GetEnumerator();
            keyInfoItems.MoveNext();

            KeyInfoX509Data keyInfoX509 = (KeyInfoX509Data)keyInfoItems.Current;

            if (keyInfoX509.Certificates.Count == 0)
            {
                //throw new CertificateInfoException("Não foi possível validar o certificado do XMl enviado.");
            }

            //buscar o certificado do KeyInfo
            X509Certificate2 keyInfoCert = (X509Certificate2)keyInfoX509.Certificates[0];
            return keyInfoCert;
        }


    }
    public enum AlgorithmSignature
    {
        /// <summary>
        /// Recomendável para criação de certificados com chave assimétrica
        /// </summary>
        Sha1 = 1,
        /// <summary>
        /// Não recomendável para criação de certificados
        /// </summary>
        Md5 = 2
    }
}
