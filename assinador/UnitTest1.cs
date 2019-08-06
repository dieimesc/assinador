using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Signature.Certificate;

namespace assinador
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            System.IO.StreamReader sr = new System.IO.StreamReader(@"C:\Users\James\teste assinatura.xml", false);
            string remessa = sr.ReadToEnd();
            sr.Close();

            X509Certificate2 xCert = CertificateLoader.FromPath("C:\\testes\\EMBUTIDOS.pfx", "12345");

            XmlDocument docRequest = new XmlDocument();
            docRequest.PreserveWhitespace = false;
            docRequest.LoadXml(sr.ReadToEnd());

            SignedXml signedXml = new SignedXml();
            XmlNodeList ListInfNFe = docRequest.GetElementsByTagName("InfRps");

            foreach (XmlElement infNFe in ListInfNFe)

            {

                string id = infNFe.Attributes.GetNamedItem("Id").InnerText;
                signedXml = new SignedXml(infNFe);
                signedXml.SigningKey = xCert.PrivateKey;

                Reference reference = new Reference("#" + id);
                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(new XmlDsigC14NTransform());
                signedXml.AddReference(reference);

                KeyInfo keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(xCert));

                signedXml.KeyInfo = keyInfo;

                signedXml.ComputeSignature();

                XmlElement xmlSignature = docRequest.CreateElement("Signature", "http://www.w3.org/2000/09/xmldsig#");
                XmlElement xmlSignedInfo = signedXml.SignedInfo.GetXml();
                XmlElement xmlKeyInfo = signedXml.KeyInfo.GetXml();

                XmlElement xmlSignatureValue = docRequest.CreateElement("SignatureValue", xmlSignature.NamespaceURI);
                string signBase64 = Convert.ToBase64String(signedXml.Signature.SignatureValue);
                XmlText text = docRequest.CreateTextNode(signBase64);
                xmlSignatureValue.AppendChild(text);

                xmlSignature.AppendChild(docRequest.ImportNode(xmlSignedInfo, true));
                xmlSignature.AppendChild(xmlSignatureValue);
                xmlSignature.AppendChild(docRequest.ImportNode(xmlKeyInfo, true));

                var evento = docRequest.GetElementsByTagName("TAG_EXTERNA_QUE_CONTERA_A_ASSINATURA");
                evento[0].AppendChild(xmlSignature);

            }



        }
    }
}
