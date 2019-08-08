using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace assinador
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Cryptography.Xml;
    using System.Text;
    using System.Xml;


    public class AssinaturaDigital
    {


        /// <summary>
        ///  
        ///     Entradas:
        ///         XMLString: string XML a ser assinada
        ///         RefUri   : Referência da URI a ser assinada (Ex. infNFe
        ///         X509Cert : certificado digital a ser utilizado na assinatura digital
        /// 
        ///     Retornos:
        ///         Assinar : 0 - Assinatura realizada com sucesso
        ///                   1 - Erro: Problema ao acessar o certificado digital - %exceção%
        ///                   2 - Problemas no certificado digital
        ///                   3 - XML mal formado + exceção
        ///                   4 - A tag de assinatura %RefUri% inexiste
        ///                   5 - A tag de assinatura %RefUri% não é unica
        ///                   6 - Erro Ao assinar o documento - ID deve ser string %RefUri(Atributo)%
        ///                  7 - Erro: Ao assinar o documento - %exceção%
        /// 
        ///         XMLStringAssinado : string XML assinada
        /// 
        ///         XMLDocAssinado    : XMLDocument do XML assinado
        ///
        /// </summary>
        /// <param name="XMLString"></param>
        /// <param name="RefUri"></param>
        /// <param name="X509Cert"></param>
        /// <returns></returns>
        public int VerificarCertificadoEAssinar(string XMLString, string RefUri, X509Certificate2 X509Cert)
        {
            int resultado = 0;
            msgResultado = "Assinatura realizada com sucesso";
            try
            {
                //   certificado para ser utilizado na assinatura
                //
                string _xnome = "";
                if (X509Cert != null)
                {
                    _xnome = X509Cert.Subject.ToString();
                }
                X509Certificate2 _X509Cert = new X509Certificate2();
                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection collection = store.Certificates;
                X509Certificate2Collection collection1 = collection.Find(X509FindType.FindBySubjectDistinguishedName, _xnome, false);
                if (collection1.Count == 0)
                {
                    resultado = 2;
                    msgResultado = "Problemas no certificado digital";
                }
                else
                {
                    // certificado ok
                    _X509Cert = collection1[0];
                    string x;
                    x = _X509Cert.GetKeyAlgorithm().ToString();
                    // Create a new XML document.
                    XmlDocument doc = new XmlDocument();

                    // Format the document to ignore white spaces.
                    doc.PreserveWhitespace = false;

                    // Load the passed XML file using it's name.
                    try
                    {
                        doc.LoadXml(XMLString);

                        // Verifica se a tag a ser assinada existe é única
                        int qtdeRefUri = doc.GetElementsByTagName(RefUri).Count;

                        if (qtdeRefUri == 0)
                        {
                            //  a URI indicada não existe
                            resultado = 4;
                            msgResultado = "A tag de assinatura " + RefUri.Trim() + " inexiste";
                        }
                        // Exsiste mais de uma tag a ser assinada
                        else
                        {
                            if (qtdeRefUri > 1)
                            {
                                // existe mais de uma URI indicada
                                resultado = 5;
                                msgResultado = "A tag de assinatura " + RefUri.Trim() + " não é unica";

                            }
                            //else if (_listaNum.IndexOf(doc.GetElementsByTagName(RefUri).Item(0).Attributes.ToString().Substring(1,1))>0)
                            //{
                            //    resultado = 6;
                            //    msgResultado = "Erro: Ao assinar o documento - ID deve ser string (" + doc.GetElementsByTagName(RefUri).Item(0).Attributes + ")";
                            //}
                            else
                            {
                                try
                                {

                                    // Create a SignedXml object.
                                    SignedXml signedXml = new SignedXml(doc);

                                    // Add the key to the SignedXml document 
                                    signedXml.SigningKey = _X509Cert.PrivateKey;

                                    // Create a reference to be signed
                                    Reference reference = new Reference();
                                    // pega o uri que deve ser assinada
                                    XmlAttributeCollection _Uri = doc.GetElementsByTagName(RefUri).Item(0).Attributes;
                                    foreach (XmlAttribute _atributo in _Uri)
                                    {
                                        if (_atributo.Name == "Id")
                                        {
                                            reference.Uri = "#" + _atributo.InnerText;
                                        }
                                    }

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
                                    keyInfo.AddClause(new KeyInfoX509Data(_X509Cert));

                                    // Add the KeyInfo object to the SignedXml object.
                                    signedXml.KeyInfo = keyInfo;

                                    signedXml.ComputeSignature();

                                    // Get the XML representation of the signature and save
                                    // it to an XmlElement object.
                                    XmlElement xmlDigitalSignature = signedXml.GetXml();

                                    // Append the element to the XML document.
                                    doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                                    XMLDoc = new XmlDocument();
                                    XMLDoc.PreserveWhitespace = false;
                                    XMLDoc = doc;
                                }
                                catch (Exception caught)
                                {
                                    resultado = 7;
                                    msgResultado = "Erro: Ao assinar o documento - " + caught.Message;
                                }
                            }
                        }
                    }
                    catch (Exception caught)
                    {
                        resultado = 3;
                        msgResultado = "Erro: XML mal formado - " + caught.Message;
                    }
                }
            }
            catch (Exception caught)
            {
                resultado = 1;
                msgResultado = "Erro: Problema ao acessar o certificado digital" + caught.Message;
                //throw new NFeInvalidCertificadoException(msgResultado, );
            }

            return resultado;
        }

        /// <summary>
        /// Assina um texto usando um certificado
        /// </summary>
        /// <param name="texto">Texto livre a ser assinado</param>
        /// <param name="X509Cert">Certificado digital a ser utilizado na assinatura digital</param>
        /// <returns>Texto Assinado</returns>
        public string AssinarTexto(string texto, X509Certificate2 X509Cert, string halgHash = "SHA256")
        {
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(texto);

                RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)X509Cert.PrivateKey;
                CspParameters csp = new CspParameters();
                csp.KeyContainerName = rsa.CspKeyContainerInfo.KeyContainerName;
                csp.KeyNumber = rsa.CspKeyContainerInfo.KeyNumber == KeyNumber.Exchange ? 1 : 2;

                rsa = new RSACryptoServiceProvider(csp);
                rsa.PersistKeyInCsp = false;

                var signedData = rsa.SignData(data, halgHash);
                return Convert.ToBase64String(signedData);

            }
            catch (Exception)
            {
                return string.Empty;
            }

        }

        /// <summary>
        ///  
        ///     Entradas:
        ///         XMLString: string XML a ser assinada
        ///         RefUri   : Referência da URI a ser assinada (Ex. infNFe
        ///         X509Cert : certificado digital a ser utilizado na assinatura digital
        /// 
        ///     Retornos:
        ///         Assinar : 0 - Assinatura realizada com sucesso
        ///                   1 - Erro: Problema ao acessar o certificado digital - %exceção%
        ///                   2 - Problemas no certificado digital
        ///                   3 - XML mal formado + exceção
        ///                   4 - A tag de assinatura %RefUri% inexiste
        ///                   5 - A tag de assinatura %RefUri% não é unica
        ///                   6 - Erro Ao assinar o documento - ID deve ser string %RefUri(Atributo)%
        ///                  7 - Erro: Ao assinar o documento - %exceção%
        /// 
        ///         XMLStringAssinado : string XML assinada
        /// 
        ///         XMLDocAssinado    : XMLDocument do XML assinado
        ///
        /// </summary>
        /// <param name="XMLString"></param>
        /// <param name="RefUri"></param>
        /// <param name="X509Cert"></param>
        /// <returns></returns>
        public int Assinar(string XMLString, string RefUri, X509Certificate2 X509Cert)
        {
            if (string.IsNullOrEmpty(RefUri))
                RefUri = "infNFe";
            int resultado = 0;
            msgResultado = "Assinatura realizada com sucesso";
            try
            {
                //   certificado para ser utilizado na assinatura
                //
                //string _xnome = "";
                if (X509Cert != null)
                {

                    // certificado ok
                    string x;
                    x = X509Cert.GetKeyAlgorithm().ToString();
                    // Create a new XML document.
                    XmlDocument doc = new XmlDocument();

                    // Format the document to ignore white spaces.
                    doc.PreserveWhitespace = false;

                    // Load the passed XML file using it's name.
                    try
                    {
                        doc.LoadXml(XMLString);

                        // Verifica se a tag a ser assinada existe é única
                        int qtdeRefUri = doc.GetElementsByTagName(RefUri).Count;

                        if (qtdeRefUri == 0)
                        {
                            //  a URI indicada não existe
                            resultado = 4;
                            msgResultado = "A tag de assinatura " + RefUri.Trim() + " inexiste";
                        }
                        // Exsiste mais de uma tag a ser assinada
                        else
                        {
                            if (qtdeRefUri > 1)
                            {
                                // existe mais de uma URI indicada
                                resultado = 5;
                                msgResultado = "A tag de assinatura " + RefUri.Trim() + " não é unica";

                            }
                            //else if (_listaNum.IndexOf(doc.GetElementsByTagName(RefUri).Item(0).Attributes.ToString().Substring(1,1))>0)
                            //{
                            //    resultado = 6;
                            //    msgResultado = "Erro: Ao assinar o documento - ID deve ser string (" + doc.GetElementsByTagName(RefUri).Item(0).Attributes + ")";
                            //}
                            else
                            {
                                try
                                {

                                    // Create a SignedXml object.
                                    SignedXml signedXml = new SignedXml(doc);

                                    // Add the key to the SignedXml document 
                                    signedXml.SigningKey = X509Cert.PrivateKey;

                                    // Create a reference to be signed
                                    Reference reference = new Reference();
                                    // pega o uri que deve ser assinada
                                    XmlAttributeCollection _Uri = doc.GetElementsByTagName(RefUri).Item(0).Attributes;
                                    foreach (XmlAttribute _atributo in _Uri)
                                    {
                                        if (_atributo.Name == "Id")
                                        {
                                            reference.Uri = "#" + _atributo.InnerText;
                                        }
                                    }

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
                                    keyInfo.AddClause(new KeyInfoX509Data(X509Cert));

                                    // Add the KeyInfo object to the SignedXml object.
                                    signedXml.KeyInfo = keyInfo;

                                    signedXml.ComputeSignature();

                                    // Get the XML representation of the signature and save
                                    // it to an XmlElement object.
                                    XmlElement xmlDigitalSignature = signedXml.GetXml();

                                    // Append the element to the XML document.
                                    doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                                    XMLDoc = new XmlDocument();
                                    XMLDoc.PreserveWhitespace = false;
                                    XMLDoc = doc;
                                }
                                catch (Exception caught)
                                {
                                    resultado = 7;
                                    msgResultado = "Erro: Ao assinar o documento - " + caught.Message;
                                }
                            }
                        }
                    }
                    catch (Exception caught)
                    {
                        resultado = 3;
                        msgResultado = "Erro: XML mal formado - " + caught.Message;
                    }
                }
            }
            catch (Exception caught)
            {
                resultado = 1;
                msgResultado = "Erro: Problema ao acessar o certificado digital" + caught.Message;
                //throw new NFeInvalidCertificadoException(msgResultado, );
            }

            return resultado;
        }

        public int Assinar(string XMLString, string RefUri, X509Certificate2 X509Cert, string RefAssinatura)
        {
            if (string.IsNullOrEmpty(RefUri))
                RefUri = "infNFe";
            int resultado = 0;
            msgResultado = "Assinatura realizada com sucesso";
            try
            {
                //   certificado para ser utilizado na assinatura
                //
                //string _xnome = "";
                if (X509Cert != null)
                {
                    // certificado ok
                    string x;
                    x = X509Cert.GetKeyAlgorithm().ToString();
                    // Create a new XML document.
                    XmlDocument doc = new XmlDocument();

                    // Format the document to ignore white spaces.
                    doc.PreserveWhitespace = false;

                    // Load the passed XML file using it's name.
                    try
                    {
                        doc.LoadXml(XMLString);

                        // Verifica se a tag a ser assinada existe é única
                        int qtdeRefUri = doc.GetElementsByTagName(RefUri).Count;

                        if (qtdeRefUri == 0)
                        {
                            //  a URI indicada não existe
                            resultado = 4;
                            msgResultado = "A tag de assinatura " + RefUri.Trim() + " inexiste";
                        }
                        // Exsiste mais de uma tag a ser assinada
                        else
                        {
                            if (qtdeRefUri > 1)
                            {
                                // existe mais de uma URI indicada
                                resultado = 5;
                                msgResultado = "A tag de assinatura " + RefUri.Trim() + " não é unica";

                            }
                            //else if (_listaNum.IndexOf(doc.GetElementsByTagName(RefUri).Item(0).Attributes.ToString().Substring(1,1))>0)
                            //{
                            //    resultado = 6;
                            //    msgResultado = "Erro: Ao assinar o documento - ID deve ser string (" + doc.GetElementsByTagName(RefUri).Item(0).Attributes + ")";
                            //}
                            else
                            {
                                try
                                {

                                    // Create a SignedXml object.
                                    SignedXml signedXml = new SignedXml(doc);

                                    // Add the key to the SignedXml document 
                                    signedXml.SigningKey = X509Cert.PrivateKey;

                                    // Create a reference to be signed
                                    Reference reference = new Reference();
                                    // pega o uri que deve ser assinada
                                    XmlAttributeCollection _Uri = doc.GetElementsByTagName(RefUri).Item(0).Attributes;
                                    foreach (XmlAttribute _atributo in _Uri)
                                    {
                                        if (_atributo.Name == "Id")
                                        {
                                            reference.Uri = "#" + _atributo.InnerText;
                                        }
                                    }

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
                                    keyInfo.AddClause(new KeyInfoX509Data(X509Cert));

                                    // Add the KeyInfo object to the SignedXml object.
                                    signedXml.KeyInfo = keyInfo;

                                    signedXml.ComputeSignature();

                                    // Get the XML representation of the signature and save
                                    // it to an XmlElement object.
                                    XmlElement xmlDigitalSignature = signedXml.GetXml();

                                    if (!string.IsNullOrEmpty(RefAssinatura))
                                    {
                                        doc.GetElementsByTagName(RefAssinatura).Item(0).AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                                    }
                                    else
                                        // Append the element to the XML document.
                                        doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                                    XMLDoc = new XmlDocument();
                                    XMLDoc.PreserveWhitespace = false;
                                    XMLDoc = doc;
                                }
                                catch (Exception caught)
                                {
                                    resultado = 7;
                                    msgResultado = "Erro: Ao assinar o documento - " + caught.Message;
                                }
                            }
                        }
                    }
                    catch (Exception caught)
                    {
                        resultado = 3;
                        msgResultado = "Erro: XML mal formado - " + caught.Message;
                    }
                }
            }
            catch (Exception caught)
            {
                resultado = 1;
                msgResultado = "Erro: Problema ao acessar o certificado digital" + caught.Message;
                //throw new NFeInvalidCertificadoException(msgResultado, );
            }

            return resultado;
        }

        public int AssinarSemID(string XMLString, X509Certificate2 X509Cert, string RefAssinatura)
        {
            int resultado = 0;
            msgResultado = "Assinatura realizada com sucesso";
            try
            {
                //   certificado para ser utilizado na assinatura
                //
                //string _xnome = "";
                if (X509Cert != null)
                {

                    // certificado ok
                    string x;
                    x = X509Cert.GetKeyAlgorithm().ToString();
                    // Create a new XML document.
                    XmlDocument doc = new XmlDocument();

                    // Format the document to ignore white spaces.
                    doc.PreserveWhitespace = false;

                    // Load the passed XML file using it's name.
                    try
                    {
                        doc.LoadXml(XMLString);


                        try
                        {

                            // Create a SignedXml object.
                            SignedXml signedXml = new SignedXml(doc);

                            // Add the key to the SignedXml document 
                            signedXml.SigningKey = X509Cert.PrivateKey;

                            // Create a reference to be signed
                            Reference reference = new Reference();
                            reference.Uri = "";

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
                            keyInfo.AddClause(new KeyInfoX509Data(X509Cert));

                            // Add the KeyInfo object to the SignedXml object.
                            signedXml.KeyInfo = keyInfo;

                            signedXml.ComputeSignature();

                            // Get the XML representation of the signature and save
                            // it to an XmlElement object.
                            XmlElement xmlDigitalSignature = signedXml.GetXml();

                            if (!string.IsNullOrEmpty(RefAssinatura))
                            {
                                doc.GetElementsByTagName(RefAssinatura).Item(0).AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                            }
                            else
                                // Append the element to the XML document.
                                doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                            XMLDoc = new XmlDocument();
                            XMLDoc.PreserveWhitespace = false;
                            XMLDoc = doc;
                        }
                        catch (Exception caught)
                        {
                            resultado = 7;
                            msgResultado = "Erro: Ao assinar o documento - " + caught.Message;
                        }

                    }
                    catch (Exception caught)
                    {
                        resultado = 3;
                        msgResultado = "Erro: XML mal formado - " + caught.Message;
                    }
                }
            }
            catch (Exception caught)
            {
                resultado = 1;
                msgResultado = "Erro: Problema ao acessar o certificado digital" + caught.Message;
                //throw new NFeInvalidCertificadoException(msgResultado, );
            }

            return resultado;
        }

        public int AssinarSemID(string XMLString, X509Certificate2 X509Cert)
        {
            int resultado = 0;
            msgResultado = "Assinatura realizada com sucesso";
            try
            {
                //   certificado para ser utilizado na assinatura
                //
                //string _xnome = "";
                if (X509Cert != null)
                {

                    // certificado ok
                    string x;
                    x = X509Cert.GetKeyAlgorithm().ToString();
                    // Create a new XML document.
                    XmlDocument doc = new XmlDocument();

                    // Format the document to ignore white spaces.
                    doc.PreserveWhitespace = false;

                    // Load the passed XML file using it's name.
                    try
                    {
                        doc.LoadXml(XMLString);


                        try
                        {

                            // Create a SignedXml object.
                            SignedXml signedXml = new SignedXml(doc);

                            // Add the key to the SignedXml document 
                            signedXml.SigningKey = X509Cert.PrivateKey;

                            // Create a reference to be signed
                            Reference reference = new Reference();
                            reference.Uri = "";

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
                            keyInfo.AddClause(new KeyInfoX509Data(X509Cert));

                            // Add the KeyInfo object to the SignedXml object.
                            signedXml.KeyInfo = keyInfo;

                            signedXml.ComputeSignature();

                            // Get the XML representation of the signature and save
                            // it to an XmlElement object.
                            XmlElement xmlDigitalSignature = signedXml.GetXml();

                            // Append the element to the XML document.
                            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                            XMLDoc = new XmlDocument();
                            XMLDoc.PreserveWhitespace = false;
                            XMLDoc = doc;
                        }
                        catch (Exception caught)
                        {
                            resultado = 7;
                            msgResultado = "Erro: Ao assinar o documento - " + caught.Message;
                        }

                    }
                    catch (Exception caught)
                    {
                        resultado = 3;
                        msgResultado = "Erro: XML mal formado - " + caught.Message;
                    }
                }
            }
            catch (Exception caught)
            {
                resultado = 1;
                msgResultado = "Erro: Problema ao acessar o certificado digital" + caught.Message;
                //throw new NFeInvalidCertificadoException(msgResultado, );
            }

            return resultado;
        }

        /// <summary>
        /// Mensagem de Retorno
        /// </summary>
        private string msgResultado;
        private XmlDocument XMLDoc;

        /// <summary>
        /// Retorno p XMLDOC
        /// </summary>
        public XmlDocument XMLDocAssinado
        {
            get { return XMLDoc; }
        }

        /// <summary>
        /// Retorno a string referente ao XMLDoc
        /// </summary>
        public string XMLStringAssinado
        {
            get { return XMLDoc.OuterXml; }
        }

        /// <summary>
        /// Retorna a Mensagem sobre a operação de assinatura
        /// </summary>
        public string mensagemResultado
        {
            get { return msgResultado; }
        }

    }

}
