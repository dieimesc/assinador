using System;
using System.IO;
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
            #region comentado
            //System.IO.StreamReader sr = new System.IO.StreamReader(@"C:\Users\James\desktop\teste assinatura.xml", false);
            //string remessa = sr.ReadToEnd();


            X509Certificate2 xCert = CertificateLoader.FromPath(@"C:\Users\James\Desktop\certificado.pfx", "quesam01");

            //XmlDocument docRequest = new XmlDocument();
            //docRequest.PreserveWhitespace = false;
            //docRequest.LoadXml(sr.ReadToEnd());

            //sr.Close();

            //SignedXml signedXml = new SignedXml();
            //XmlNodeList ListInfNFe = docRequest.GetElementsByTagName("InfRps");

            //foreach (XmlElement infNFe in ListInfNFe)

            //{

            //    string id = infNFe.Attributes.GetNamedItem("Id").InnerText;
            //    signedXml = new SignedXml(infNFe);
            //    signedXml.SigningKey = xCert.PrivateKey;

            //    Reference reference = new Reference("#" + id);
            //    reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            //    reference.AddTransform(new XmlDsigC14NTransform());
            //    signedXml.AddReference(reference);

            //    KeyInfo keyInfo = new KeyInfo();
            //    keyInfo.AddClause(new KeyInfoX509Data(xCert));

            //    signedXml.KeyInfo = keyInfo;

            //    signedXml.ComputeSignature();

            //    XmlElement xmlSignature = docRequest.CreateElement("Signature", "http://www.w3.org/2000/09/xmldsig#");
            //    XmlElement xmlSignedInfo = signedXml.SignedInfo.GetXml();
            //    XmlElement xmlKeyInfo = signedXml.KeyInfo.GetXml();

            //    XmlElement xmlSignatureValue = docRequest.CreateElement("SignatureValue", xmlSignature.NamespaceURI);
            //    string signBase64 = Convert.ToBase64String(signedXml.Signature.SignatureValue);
            //    XmlText text = docRequest.CreateTextNode(signBase64);
            //    xmlSignatureValue.AppendChild(text);

            //    xmlSignature.AppendChild(docRequest.ImportNode(xmlSignedInfo, true));
            //    xmlSignature.AppendChild(xmlSignatureValue);
            //    xmlSignature.AppendChild(docRequest.ImportNode(xmlKeyInfo, true));

            //    var evento = docRequest.GetElementsByTagName("TAG_EXTERNA_QUE_CONTERA_A_ASSINATURA");
            //    evento[0].AppendChild(xmlSignature);

            //}

            #endregion

            AssinarXml(@"C:\Users\James\desktop\teste assinatura.xml", "EnviarLoteRpsEnvio", "LoteRps", xCert);
            AssinarXml(@"C:\Users\James\desktop\teste assinatura.xml", "Rps", "InfRps", xCert);



        }
        private void AssinarXml(string arquivo, string tagAssinatura, string tagAtributoId, X509Certificate2 x509Cert)
        {
            StreamReader SR = null;

            try
            {
                SR = File.OpenText(arquivo);
                string xmlString = SR.ReadToEnd();
                SR.Close();
                SR = null;

                // Create a new XML document.
                XmlDocument doc = new XmlDocument();

                // Format the document to ignore white spaces.
                doc.PreserveWhitespace = false;

                // Load the passed XML file using it’s name.
                doc.LoadXml(xmlString);

                if (doc.GetElementsByTagName(tagAssinatura).Count == 0)
                {
                    throw new Exception("A tag de assinatura " + tagAssinatura.Trim() + " não existe no XML. (Código do Erro: 5)");
                }
                else if (doc.GetElementsByTagName(tagAtributoId).Count == 0)
                {
                    throw new Exception("A tag de assinatura " + tagAtributoId.Trim() + " não existe no XML. (Código do Erro: 4)");
                }
                else
                {
                    XmlDocument XMLDoc;

                    XmlNodeList lists = doc.GetElementsByTagName(tagAssinatura);
                    foreach (XmlNode nodes in lists)
                    {
                        foreach (XmlNode childNodes in nodes.ChildNodes)
                        {
                            if (!childNodes.Name.Equals(tagAtributoId))
                                continue;

                            if (childNodes.NextSibling != null && childNodes.NextSibling.Name.Equals("Signature"))
                                continue;

                            // Create a reference to be signed
                            Reference reference = new Reference();
                            reference.Uri = "";

                            XmlElement childElemen = (XmlElement)childNodes;
                            if (childElemen.GetAttributeNode("Id") != null)
                            {
                                reference.Uri = ""; // "#" + childElemen.GetAttributeNode("Id").Value;
                            }
                            else if (childElemen.GetAttributeNode("id") != null)
                            {
                                reference.Uri = "#" + childElemen.GetAttributeNode("id").Value;
                            }

                            // Create a SignedXml object.
                            SignedXml signedXml = new SignedXml(doc);

                            // Add the key to the SignedXml document
                            signedXml.SigningKey = x509Cert.PrivateKey;

                            // Add an enveloped transformation to the reference.
                            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
                            reference.AddTransform(env);

                            XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
                            reference.AddTransform(c14);

                            // Add the reference to the SignedXml object.
                            signedXml.AddReference(reference);

                            // Create a new KeyInfo object
                            KeyInfo keyInfo = new KeyInfo();

                            // Load the certificate into a KeyInfoX509Data object
                            // and add it to the KeyInfo object.
                            keyInfo.AddClause(new KeyInfoX509Data(x509Cert));

                            // Add the KeyInfo object to the SignedXml object.
                            signedXml.KeyInfo = keyInfo;
                            signedXml.ComputeSignature();

                            // Get the XML representation of the signature and save
                            // it to an XmlElement object.
                            XmlElement xmlDigitalSignature = signedXml.GetXml();

                            nodes.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                        }
                    }

                    XMLDoc = new XmlDocument();
                    XMLDoc.PreserveWhitespace = false;
                    XMLDoc = doc;

                    string conteudoXMLAssinado = XMLDoc.OuterXml;

                    using (StreamWriter sw = File.CreateText(arquivo))
                    {
                        sw.Write(conteudoXMLAssinado);
                        sw.Close();
                    }
                }
            }
            finally
            {
                if (SR != null)
                    SR.Close();
            }
        }
    }
}
