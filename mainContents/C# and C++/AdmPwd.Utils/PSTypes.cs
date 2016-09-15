using System;
using System.Collections.Generic;
using System.Text;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using System.Xml.Linq;
using System.Linq;

namespace AdmPwd.PSTypes
{
    #region Enums

    public enum SchemaObjectType
    {
        Attribute = 0,
        Class
    }

    public enum PasswordResetState
    {
        PasswordReset = 0
    }

    public enum PermissionDelegationState
    {
        Unknown = 0,
        Delegated
    }

    public enum DirectoryOperationType
    {
        AddSchemaAttribute = 0,
        ModifySchemaClass
    }

    #endregion

    #region Output data
    public class ExtendedRightsInfo
    {
        public string ObjectDN;
        public List<string> ExtendedRightHolders = new List<string>();
        public ExtendedRightsInfo(string dn)
        {
            ObjectDN = dn;
        }
    }

    public class PasswordInfo
    {
        public string ComputerName;
        public string DistinguishedName;
        public string Password;
        public DateTime ExpirationTimestamp;
        public PasswordInfo(string DistinguishedName)
        {
            this.DistinguishedName = DistinguishedName;
        }
    }

    public class ObjectInfo
    {
        public string Name;
        public string DistinguishedName;
        public PermissionDelegationState Status;
    }

    public class ForestInfo
    {
        public DomainInfo rootDomain;
        public string configurationNamingContext;
        public string schemaNamingContext;
        public ForestInfo()
        {
            rootDomain = new DomainInfo();
        }
    }

    public class DomainInfo
    {
        public string DnsName;
        public string dn;
        public string ConnectedHost;
        public SecurityIdentifier sid;
    }

    public class PasswordResetStatus
    {
        public string DistinguishedName;
        public PasswordResetState Status;

        public PasswordResetStatus(string dn, PasswordResetState state)
        {
            DistinguishedName = dn;
            Status = state;
        }
    }

    public class DirectoryOperationStatus
    {
        public DirectoryOperationType Operation;
        public string DistinguishedName;
        public ResultCode Status;

        public DirectoryOperationStatus(DirectoryOperationType op, string dn, ResultCode state)
        {
            Operation = op;
            DistinguishedName = dn;
            Status = state;
        }
    }
    #endregion

}