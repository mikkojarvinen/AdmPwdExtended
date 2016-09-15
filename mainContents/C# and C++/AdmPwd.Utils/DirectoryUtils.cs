using System;
using System.Collections.Generic;
using System.Text;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using System.Xml.Linq;
using System.Linq;
using AdmPwd.PSTypes;

namespace AdmPwd.Utils
{
    #region Classes
    public class Constants
    {
        public static string CSEString = "[{D76B9641-3288-4f75-942D-087DE603E3EA}{D76B9641-3288-4f75-942D-087DE603E3EA}]";

        static string ConfigFile="AdmPwd.Utils.config";
        public static string TimestampAttributeName
        {
            get
            {
                string codeBase = System.Reflection.Assembly.GetExecutingAssembly().CodeBase;
                string basePath = System.IO.Path.GetDirectoryName(codeBase);
                string configPath = System.IO.Path.Combine(basePath, ConfigFile);

                XElement root = XElement.Load(configPath);
                return root.Descendants("add").Where(x => x.Attribute("key").Value == "timestampAttribute").FirstOrDefault().Attribute("value").Value;
            }
        }

        public static string PasswordAttributeName
        {
            get
            {
                string codeBase = System.Reflection.Assembly.GetExecutingAssembly().CodeBase;
                string basePath = System.IO.Path.GetDirectoryName(codeBase);
                string configPath = System.IO.Path.Combine(basePath, ConfigFile);

                XElement root = XElement.Load(configPath);
                return root.Descendants("add").Where(x => x.Attribute("key").Value == "pwdAttribute").FirstOrDefault().Attribute("value").Value;
            }
        }
    }

    public static class DirectoryUtils
    {
        public static LdapConnection GetLdapConnection(ConnectionType type)
        {
            return new LdapConnection(new LdapDirectoryIdentifier(string.Empty, (int)type));
        }

        public static LdapConnection GetLdapConnection(string serverName, ConnectionType type)
        {
            return new LdapConnection(new LdapDirectoryIdentifier(serverName, (int)type));
        }


        //returns search result as list of distinguishedNames
        //[DirectoryServicesPermissionAttribute(SecurityAction.LinkDemand, Unrestricted = true)]
        public static List<string> Search(string filter, string baseDN, string propToLoad = "distinguishedName", int pageSize = 0)
        {
            List<string> retVal = new List<string>();
            LdapConnection conn = GetLdapConnection(ConnectionType.LDAP);

            SearchRequest rq = new SearchRequest(baseDN, filter, System.DirectoryServices.Protocols.SearchScope.Subtree, propToLoad);
            //we need to perform a paged search here
            PageResultRequestControl pagedRqc = new PageResultRequestControl(pageSize);
            if (pageSize > 0)
            {
                rq.Controls.Add(pagedRqc);
            }
            rq.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            bool processingFinished = false;
            while (!processingFinished)
            {
                SearchResponse rsp = conn.SendRequest(rq) as SearchResponse;
                if (pageSize > 0)
                {
                    PageResultResponseControl prrc = null;
                    if (rsp.Controls.Length > 0)
                    {
                        foreach (DirectoryControl ctrl in rsp.Controls)
                        {
                            if (ctrl is PageResultResponseControl)
                            {
                                prrc = ctrl as PageResultResponseControl;
                                break;
                            }
                        }
                    }
                    if (prrc == null)
                        throw new DirectoryOperationException("Paging is not supported");
                    if (prrc.Cookie.Length == 0)
                        //last page --> we're done
                        processingFinished = true;
                    else
                        pagedRqc.Cookie = prrc.Cookie;

                }
                else
                    processingFinished = true;
                foreach (SearchResultEntry sr in rsp.Entries)
                {
                    retVal.Add(sr.DistinguishedName);
                }
            }
            return retVal;
        }
        
        public static Guid GetSchemaGuid(LdapConnection conn, string schemaNcDn, string objectName, SchemaObjectType objectType)
        {
            SearchRequest rq = new SearchRequest();
            switch (objectType)
            {
                case SchemaObjectType.Attribute:
                    rq.Filter = string.Format("(&(objectClass=attributeSchema)(cn={0}))", objectName);
                    break;
                case SchemaObjectType.Class:
                    rq.Filter = string.Format("(&(objectClass=classSchema)(cn={0}))", objectName);
                    break;
                default:
                    rq.Filter = string.Format("(cn={0})", objectName);
                    break;
            }
            rq.DistinguishedName = schemaNcDn;
            rq.Attributes.Add("schemaIDGuid");

            SearchResponse rsp = (SearchResponse)conn.SendRequest(rq);
            if (rsp.Entries.Count == 0)
                throw new DirectoryOperationException("No such object found");
            byte[] rawGuid = rsp.Entries[0].Attributes["schemaidguid"].GetValues(typeof(byte[]))[0] as byte[];
            return new Guid(rawGuid);
        }

        public static void SetObjectSecurity(LdapConnection conn, string dn, System.DirectoryServices.ActiveDirectorySecurity sec, System.DirectoryServices.Protocols.SecurityMasks securityMask)
        {
            byte[] rawSD = sec.GetSecurityDescriptorBinaryForm();

            //get securityDescriptor
            ModifyRequest modRq = new ModifyRequest(dn,DirectoryAttributeOperation.Replace,"ntSecurityDescriptor",rawSD);
            modRq.Controls.Add(new SecurityDescriptorFlagControl(securityMask));
            ModifyResponse rsp = (ModifyResponse)conn.SendRequest(modRq);

        }
        
        public static System.DirectoryServices.ActiveDirectorySecurity GetObjectSecurity(LdapConnection conn, string dn, System.DirectoryServices.Protocols.SecurityMasks securityMask)
        {
            System.DirectoryServices.ActiveDirectorySecurity retVal = new System.DirectoryServices.ActiveDirectorySecurity();

            //get securityDescriptor
            SearchRequest searchRq = new SearchRequest(dn, string.Format("(distinguishedName={0})", dn), System.DirectoryServices.Protocols.SearchScope.Base, "ntSecurityDescriptor");
            searchRq.Controls.Add(new SecurityDescriptorFlagControl(securityMask));
            SearchResponse rsp = (SearchResponse)conn.SendRequest(searchRq);

            foreach (SearchResultEntry sr in rsp.Entries)
            {
                byte[] ntSecurityDescriptor = sr.Attributes["ntsecuritydescriptor"].GetValues(typeof(byte[]))[0] as byte[];
                retVal.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
            }

            return retVal;
        }
        
        public static ForestInfo GetForestRootDomain()
        {
            ForestInfo retVal = new ForestInfo();
            string[] propsToLoad = new string[] { "rootDomainNamingContext", "configurationNamingContext", "schemaNamingContext","dnsHostName" };
            using (LdapConnection conn = GetLdapConnection(ConnectionType.LDAP))
            {
                SearchRequest rq = new SearchRequest();
                rq.Attributes.AddRange(propsToLoad);
                rq.Scope = SearchScope.Base;
                ExtendedDNControl ctrl = new ExtendedDNControl(ExtendedDNFlag.StandardString);
                rq.Controls.Add(ctrl);
                SearchResponse rsp = (SearchResponse)conn.SendRequest(rq);

                string rootNC = (rsp.Entries[0].Attributes["rootDomainNamingContext"].GetValues(typeof(string)))[0] as string;
                int start = rootNC.IndexOf("<SID=", StringComparison.CurrentCultureIgnoreCase);
                if (start > -1)
                {
                    retVal.rootDomain.dn = rootNC.Split(';')[2];
                    int end = rootNC.IndexOf('>', start);
                    start += 5; //prefix of SID: <SID=

                    string sid = rootNC.Substring(start, end - start);
                    retVal.rootDomain.sid = new SecurityIdentifier(sid);
                }

                retVal.configurationNamingContext = ((rsp.Entries[0].Attributes["configurationNamingContext"].GetValues(typeof(string)))[0] as string).Split(';')[1];
                retVal.schemaNamingContext = ((rsp.Entries[0].Attributes["schemaNamingContext"].GetValues(typeof(string)))[0] as string).Split(';')[1];
                retVal.rootDomain.ConnectedHost = rsp.Entries[0].Attributes["dnsHostName"].GetValues(typeof(string))[0] as string;
                //get DNS name of forest root domain
                rq = new SearchRequest();
                rq.DistinguishedName = "cn=Partitions," + retVal.configurationNamingContext;
                rq.Scope = SearchScope.OneLevel;
                rq.Attributes.Add("dnsRoot");
                rq.Filter = string.Format("(&(objectClass=crossRef)(nCName={0}))", retVal.rootDomain.dn);
                rsp = (SearchResponse)conn.SendRequest(rq);
                retVal.rootDomain.DnsName = rsp.Entries[0].Attributes["dnsRoot"].GetValues(typeof(string))[0] as string;
            }
            return retVal;
        }
        
        public static List<DomainInfo> GetForestDomains(LdapConnection conn)
        {
            if (conn == null)
                throw new NullReferenceException();
            string[] propsToLoad = new string[] { "namingContexts", "configurationNamingContext" };
            List<DomainInfo> retVal = new List<DomainInfo>();
            SearchRequest rq = new SearchRequest();
            rq.Attributes.AddRange(propsToLoad);
            rq.Scope = SearchScope.Base;
            ExtendedDNControl ctrl = new ExtendedDNControl(ExtendedDNFlag.StandardString);
            rq.Controls.Add(ctrl);
            SearchResponse rsp = (SearchResponse)conn.SendRequest(rq);

            foreach (string nc in (string[])(rsp.Entries[0].Attributes["namingContexts"].GetValues(typeof(string))))
            {
                int start = nc.IndexOf("<SID=", StringComparison.CurrentCultureIgnoreCase);
                if (start > -1)
                {
                    DomainInfo di = new DomainInfo();
                    di.dn = nc.Split(';')[2];
                    int end = nc.IndexOf('>', start);
                    start += 5; //prefix of SID: <SID=

                    string sid = nc.Substring(start, end - start);
                    di.sid = new SecurityIdentifier(sid);

                    retVal.Add(di);
                }
            }
            string configNC = ((rsp.Entries[0].Attributes["configurationNamingContext"].GetValues(typeof(string)))[0] as string).Split(';')[1];
            foreach (DomainInfo di in retVal)
            {
                rq = new SearchRequest();
                rq.DistinguishedName = "cn=Partitions," + configNC;
                rq.Scope = SearchScope.OneLevel;
                rq.Attributes.Add("dnsRoot");
                rq.Filter = string.Format("(&(objectClass=crossRef)(nCName={0}))", di.dn);
                rsp = (SearchResponse)conn.SendRequest(rq);
                di.DnsName = rsp.Entries[0].Attributes["dnsRoot"].GetValues(typeof(string))[0] as string;
            }

            return retVal;
        }

        public static List<ObjectInfo> GetOU(string identity)
        {
            //searching against default domain controller and GC interface
            List<ObjectInfo> retVal = new List<ObjectInfo>();
            string[] propsToLoad = { "name" };
            using (var connGC = GetLdapConnection(ConnectionType.GC))
            {
                SearchRequest rq = new SearchRequest();
                rq.Attributes.AddRange(propsToLoad);
                if (identity.StartsWith("ou=", StringComparison.CurrentCultureIgnoreCase) || identity.StartsWith("cn=", StringComparison.CurrentCultureIgnoreCase) || identity.StartsWith("dc=", StringComparison.CurrentCultureIgnoreCase))
                {
                    rq.Filter = string.Format("(distinguishedName={0})", identity);
                    rq.Scope = SearchScope.Base;
                    rq.DistinguishedName = identity;
                }
                else
                {
                    rq.Filter = string.Format("(&(objectClass=organizationalUnit)(objectCategory=organizationalUnit)(ou={0}))", identity);
                    rq.Scope = SearchScope.Subtree;
                }
                SearchResponse rsp = (SearchResponse)connGC.SendRequest(rq);
                foreach (SearchResultEntry sr in rsp.Entries)
                {
                    ObjectInfo oui = new ObjectInfo();
                    oui.DistinguishedName = sr.DistinguishedName;
                    foreach (string attrName in sr.Attributes.AttributeNames)
                    {
                        switch (attrName)
                        {
                            case "name":
                                oui.Name = sr.Attributes[attrName].GetValues(typeof(string))[0] as string;
                                break;
                        }
                    }
                    retVal.Add(oui);
                }
            }
            return retVal;
        }

        public static List<string> GetComputerDN(string ComputerName)
        {
            //searching against default domain controller and GC interface
            List<string> retVal = new List<string>();
            using (LdapConnection connGC = GetLdapConnection(ConnectionType.GC))
            {
                ForestInfo di = GetForestRootDomain();
                SearchRequest rq = new SearchRequest();
                string searchString = string.Format("(&(objectClass=computer)(cn={0}))", ComputerName);
                rq = new SearchRequest();
                rq.Filter=searchString;
                rq.Scope=SearchScope.Subtree;
                SearchResponse rsp = (SearchResponse)connGC.SendRequest(rq);
                foreach (SearchResultEntry sr in rsp.Entries)
                    retVal.Add(sr.DistinguishedName);
            }
            return retVal;
        }

        public static PasswordInfo GetPasswordInfo(string computerDN)
        {
            string[] propsToLoad = { "cn", Constants.PasswordAttributeName, Constants.TimestampAttributeName };
            PasswordInfo pi = new PasswordInfo(computerDN);

            using (LdapConnection conn = GetLdapConnection(ConnectionType.LDAP))
            {
                conn.SessionOptions.ReferralChasing = ReferralChasingOptions.All;
                //require Kerberos encryption so as password is protected when transferring over the network
                conn.SessionOptions.Sealing = true;
                conn.SessionOptions.Signing = true;

                SearchRequest rq = new SearchRequest(computerDN, string.Format("(&(objectClass=computer)(distinguishedName={0}))", computerDN), SearchScope.Base, propsToLoad);
                SearchResponse rsp = (SearchResponse)conn.SendRequest(rq);
                foreach (SearchResultEntry sr in rsp.Entries)
                {
                    foreach (string attrName in sr.Attributes.AttributeNames)
                    {
                        if(string.Compare(attrName,"cn",true)==0)
                            pi.ComputerName = sr.Attributes[attrName].GetValues(typeof(string))[0] as string;
                        else if(string.Compare(attrName,Constants.PasswordAttributeName,true)==0)
                            pi.Password = sr.Attributes[attrName].GetValues(typeof(string))[0] as string;
                        else if (string.Compare(attrName, Constants.TimestampAttributeName, true) == 0)
                        {
                            string timestamp = sr.Attributes[Constants.TimestampAttributeName.ToLower()].GetValues(typeof(string))[0] as string;
                            if (!string.IsNullOrEmpty(timestamp))
                            {
                                long ts = long.Parse(timestamp);
                                pi.ExpirationTimestamp = DateTime.FromFileTime(ts);
                            }
                        }
                    }
                }
            }
            return pi;
        }

        public static void ResetPassword(string computerDn, DateTime WhenEffective)
        {
            if (WhenEffective == DateTime.MinValue)
                WhenEffective = DateTime.Now;

            using (LdapConnection conn = GetLdapConnection(ConnectionType.LDAP))
            {
                conn.SessionOptions.ReferralChasing = ReferralChasingOptions.All;
                //not absolutely necessary as we do not transfer password here, but let's behave consistently when dealing with computer object
                conn.SessionOptions.Sealing = true;
                conn.SessionOptions.Signing = true;
                ModifyRequest rq = new ModifyRequest();
                rq.DistinguishedName = computerDn;
                DirectoryAttributeModification mod = new DirectoryAttributeModification();
                mod.Name = Constants.TimestampAttributeName;
                mod.Operation = DirectoryAttributeOperation.Replace;
                mod.Add(WhenEffective.ToFileTime().ToString("D"));

                rq.Modifications.Add(mod);
                conn.SendRequest(rq);
            }
        }
    }

    #endregion

    #region Enums
    public enum ConnectionType
    {
        LDAP = 389,
        GC = 3268
    };


    #endregion


}
