using System;
using System.Collections.Generic;
using System.Text;

namespace Signature.Certificate
{
    public struct CertificateInfo
    {
        private string _name;
        private string _subject;
        private DateTime _dateIssue;
        private DateTime _dateExpiration;
        private string _password;
        private AlgorithmSignature _algorithm;
        private string _fileName;

        public string Name
        {
            get { return _name; }
            set
            {
                _name = value;
                _subject = value;
            }
        }
        public string Subject
        {
            get { return _subject; }
            set { _subject = value; }
        }
        public DateTime DateIssue
        {
            get { return _dateIssue; }
            set { _dateIssue = value; }
        }
        public DateTime DateExpiration
        {
            get { return _dateExpiration; }
            set
            {
                _dateExpiration = value;//.Date.AddMonths(6);
            }
        }
        public string Password
        {
            get { return _password; }
            set { _password = value; }
        }
        public AlgorithmSignature Algorithm
        {
            get { return _algorithm; }
            set { _algorithm = value; }
        }
        public string FileName
        {
            get { return _fileName; }
            set { _fileName = value; }
        }
    }
}
