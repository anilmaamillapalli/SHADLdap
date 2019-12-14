package com.sh.ldap;

import Thor.API.Operations.tcLookupOperationsIntf;
import Thor.API.tcResultSet;

import java.util.HashMap;
import java.util.Hashtable;

import java.util.Map;

import java.util.logging.Level;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;

import javax.naming.directory.InitialDirContext;

import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;

import javax.naming.directory.SearchResult;

import javax.security.auth.login.LoginException;

import oracle.iam.platform.OIMClient;
import oracle.iam.platform.Platform;

public class OIMLdapConnect {
    public OIMLdapConnect() {
        super();
    }
    
    public enum GeneralConstants { OBJ_CLASS("objectClass"), 
                                   USER("user"), 
                                   PERSON("Person"),
                                   ORG_PERSON("organizationalPerson"),
                                   TOP("top"),
                                   SN("sn"),
                                   CN("cn"),
                                   NAME("name"),
                                   GIVEN_NAME("givenName"),
                                   DISPLAY_NAME("displayName"),
                                   UPN("userPrincipalName"),
                                   DESC("description"),
                                   TITLE("title"),
                                   DEPT("department"),
                                   SAM_ACCOUNT("sAMAccountName"),
                                   COMPANY("company"),
                                   MANAGER("manager"),
                                   ITRESOURCE_NAME("IT Resources.Name"),
                                   ITRESOURCE_KEY("IT Resources.Key"),
                                   ITRESOURCE_TYPE_PARA_NAME("IT Resources Type Parameter.Name"),
                                   ITRESOURCE_TYPE_PARA_VALUE("IT Resources Type Parameter Value.Value"),
                                   CONTEXT_FACTORY("com.sun.jndi.ldap.LdapCtxFactory"),
                                   SECURITY_AUTH("simple")               
                                       
                                       public  String value;
                                       private GeneralConstants(String  value) {
                                           this.value=value;
                                       }
                                       public String getValue() {
                                           return this.value;
                                       };
                               
                                   
                                   };
    

    
    
    public OIMClient getOIMConnection() {

        Hashtable<Object, Object> env = new Hashtable<Object, Object>();
        env.put(OIMClient.JAVA_NAMING_FACTORY_INITIAL, "weblogic.jndi.WLInitialContextFactory");
        env.put(OIMClient.JAVA_NAMING_PROVIDER_URL, "t3://vmlxwlgcfot01:14000");
        System.setProperty("java.security.auth.login.config","C:\\TestDC\\designconsole\\config\\authwl.conf"); 
        System.setProperty("OIM.AppServerType", "wls");
        System.setProperty("APPSERVER_TYPE", "wls");
        oracle.iam.platform.OIMClient oimClient =  new oracle.iam.platform.OIMClient(env);

        try {
            oimClient.login("xelsysadm",  "o1g4H3@lth17".toCharArray());
            System.out.print("Successfully Connected with OIM ");
        } catch (LoginException e) {
            System.out.print("Login Exception" + e);
        }
        return oimClient;
    }
    
    
    
    public void getITResourceParameter(String ITResourceName) throws NumberFormatException, Exception {
   
        Map phAttributeList = new HashMap();
            phAttributeList.put(GeneralConstants.ITRESOURCE_NAME.toString(), ITResourceName);
            
            
        OIMLdapConnect oimLdapConnection= new OIMLdapConnect();
        OIMClient oimClient= oimLdapConnection.getOIMConnection();
          
        HashMap<String,String> paramMap = new HashMap<String,String>();
        Thor.API.Operations.tcITResourceInstanceOperationsIntf ITResourceAPI = (Thor.API.Operations.tcITResourceInstanceOperationsIntf)oimClient.getService(Thor.API.Operations.tcITResourceInstanceOperationsIntf.class);
        Thor.API.tcResultSet itresSet = ITResourceAPI.findITResourceInstances(phAttributeList);
        itresSet.goToRow(0);
        String ITResourceKey = itresSet.getStringValue(GeneralConstants.ITRESOURCE_KEY.toString());
        System.out.println("ITResourceKey::"+ITResourceKey);
        Thor.API.tcResultSet paramValuesRS = ITResourceAPI.getITResourceInstanceParameters(Long.parseLong(ITResourceKey));
        
        
        for(int j=0;j<paramValuesRS.getTotalRowCount();j++){
              paramValuesRS.goToRow(j);
              paramMap.put(paramValuesRS.getStringValue(GeneralConstants.ITRESOURCE_TYPE_PARA_NAME.toString()), paramValuesRS.getStringValue(GeneralConstants.ITRESOURCE_TYPE_PARA_VALUE.toString()));
        }
   
            for(Map.Entry m:paramMap.entrySet()){    
                   System.out.println((String)m.getKey()+" "+m.getValue());    
                  }  
   }
    
    
    
    
public DirContext ldapConnect()throws NamingException {
        

        Hashtable env = new Hashtable();
            env.put(Context.INITIAL_CONTEXT_FACTORY, GeneralConstants.CONTEXT_FACTORY.toString());
            env.put(Context.PROVIDER_URL, "ldap://vmmsdcthft08.sh-test.org:389");
           // env.put(Context.REFERRAL, "throw");
            env.put(Context.SECURITY_AUTHENTICATION,GeneralConstants.SECURITY_AUTH.toString());
            //env.put(Context.SECURITY_CREDENTIALS, "craDun!vE8tErUK");
            env.put(Context.SECURITY_CREDENTIALS, "MakIsAwesome!");
            env.put(Context.SECURITY_PRINCIPAL, "adminani91176@sh-test.org");
           // env.put(Context.SECURITY_PRINCIPAL, "svc_oimtad@sh-test.org");

            //env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            //env.put(Context.PROVIDER_URL, "ldap://192.168.29.165:2389/dc=EnterpriseDR,dc=advantageit,dc=com");
            //env.put(Context.REFERRAL, "throw");
            //env.put(Context.SECURITY_AUTHENTICATION,"simple");
            //env.put(Context.SECURITY_CREDENTIALS, "Passw0rd");
            //env.put(Context.SECURITY_PRINCIPAL, "cn=directory manager");
        DirContext dirContext = new InitialDirContext(env);
   
    if(dirContext != null) {
            System.out.println("We have established connection");
            return dirContext;
    }else {
           System.out.println("can not established connection");
           return null;
    }
  
}



    private void createLDAPObject(String name) throws NamingException,
                                                       Exception {
           
   
            OIMLdapConnect oimLdapConnection= new OIMLdapConnect();
            DirContext ctx = oimLdapConnection.ldapConnect();

            Attributes attributes = new BasicAttributes();
     
            Attribute attribute = new BasicAttribute(GeneralConstants.OBJ_CLASS.toString());
            attribute.add(GeneralConstants.USER.toString());
            attribute.add(GeneralConstants.PERSON.toString());
            attribute.add(GeneralConstants.ORG_PERSON.toString());
            attribute.add(GeneralConstants.TOP.toString());    
            attributes.put(attribute);
     
           //surname
            Attribute sn = new BasicAttribute(GeneralConstants.SN.toString());
            sn.add(name);
            attributes.put(sn);
            
//            Attribute accountPassword = new BasicAttribute("UnicodePwd");
//            accountPassword.add("Passw0rd1");
//            attributes.put(accountPassword);
            
     
            Attribute cn = new BasicAttribute(GeneralConstants.CN.toString());
            cn.add(name);
            attributes.put(cn);
            
            Attribute name1 = new BasicAttribute(GeneralConstants.NAME.toString());
            name1.add(name);
            attributes.put(name1);
            
            Attribute givenName = new BasicAttribute(GeneralConstants.GIVEN_NAME.toString());
            givenName.add(name);
            attributes.put(givenName);
            
            Attribute displayName = new BasicAttribute(GeneralConstants.DISPLAY_NAME.toString());
            displayName.add(name);
            attributes.put(displayName);
            
            Attribute userPrincipalName = new BasicAttribute(GeneralConstants.UPN.toString());
            userPrincipalName.add(name+"@SH-Test.org");
            attributes.put(userPrincipalName);
            
            Attribute description = new BasicAttribute(GeneralConstants.DESC.toString());
            description.add(name);
            attributes.put(description);
            
            Attribute title = new BasicAttribute(GeneralConstants.TITLE.toString());
            title.add(name);
            attributes.put(title);
            
            
            Attribute department = new BasicAttribute(GeneralConstants.DEPT.toString());
            department.add(name);
            attributes.put(department);
            
            Attribute sAMAccountName = new BasicAttribute(GeneralConstants.SAM_ACCOUNT.toString());
            sAMAccountName.add(name);
            attributes.put(sAMAccountName);
            
            Attribute Company = new BasicAttribute(GeneralConstants.COMPANY.toString());
            Company.add(name);
            attributes.put(Company);
            
            String fqdnManager=getUserDn("AALANNN");
            System.out.println(fqdnManager);
            Attribute manager = new BasicAttribute(GeneralConstants.MANAGER.toString());
            manager.add(fqdnManager);
            attributes.put(manager);
            
                       
            ctx.createSubcontext(GeneralConstants.CN.toString()+"="+name+",OU=ServiceAccounts,DC=SH-Test,DC=org", attributes);
  
        }




    private  String getUserDn (String user) throws Exception {
                OIMLdapConnect oimLdapConnection= new OIMLdapConnect();
                DirContext ctx = oimLdapConnection.ldapConnect();
                String defaultSearchBase = "DC=SH-Test,DC=org";
                    String filter = "(cn=" + user + ")";
                    SearchControls ctrl = new SearchControls();
                
                    ctrl.setSearchScope(SearchControls.SUBTREE_SCOPE);
                    NamingEnumeration answer = ctx.search(defaultSearchBase, filter, ctrl);

                    String dn;
                    if (answer.hasMore()) {
                            SearchResult result = (SearchResult) answer.next();
                            dn = result.getNameInNamespace();
                    }
                    else {
                          dn = null;
                    }
                    answer.close();
                    System.out.println(dn);
                    return dn;
            }


    public void assingGrouptoUser(String username, String groupName) throws NamingException    {
           OIMLdapConnect oimLdapConnection= new OIMLdapConnect();
           DirContext dirContext = oimLdapConnection.ldapConnect();
       try {    
            ModificationItem[] mods = new ModificationItem[1];
            Attribute mod =new BasicAttribute(GeneralConstants.MANAGER.toString(),  getUserDn (username));
            mods[0] =  new ModificationItem(DirContext.ADD_ATTRIBUTE, mod);
            dirContext.modifyAttributes(groupName, mods);
           
        } catch (Exception e) {
            System.out.println("no_assignment "+username+":"+groupName);
            e.printStackTrace();
        }
       }


//    public static Map<String, String> getKeyValuePairsfromLookup(String lookupName) throws Exception {
//            //  logger.log(Level.INFO, "Executing getKeyValuePairsfromLookup(String lookupName) : get the code key and decode");
//                OIMLdapConnect oimLdapConnection= new OIMLdapConnect();
//                OIMClient oimClient = oimLdapConnection.getOIMConnection();
//                tcLookupOperationsIntf lookupOperationsService =(tcLookupOperationsIntf)oimClient.getService(tcLookupOperationsIntf.class);
//                    Map<String, String> lookupKeyValueMap = new HashMap<String, String>();
//                    tcResultSet lookupResultSet;
//                    String key, value = null;
//                    try {
//                            lookupResultSet = lookupOperationsService.getLookupValues(lookupName);
//                            if (null != lookupResultSet && !(lookupResultSet.isEmpty())) {
//                                    int i = 0;
//                                    while (i < lookupResultSet.getRowCount()) {
//                                            lookupResultSet.goToRow(i);
//                                            key = lookupResultSet.getStringValue(SHLSchedulerConstants.CODE_KEY.getValue());
//                                            value = lookupResultSet.getStringValue(SHLSchedulerConstants.DECODE.getValue());
//                                            if (!(SHLUtils.isEmpty(key)) && !(SHLUtils.isEmpty(value))) {
//                                               lookupKeyValueMap.put(key, value);
//                                            }
//                                            i++;
//                                    }
//                            }
//                    } catch (Exception e) {
//                      logger.log(Level.SEVERE,e.getMessage());
//                      throw e;
//                  }
//                logger.log(Level.INFO,"Exiting getKeyValuePairsfromLookup(String lookupName) : Map<String, String>");
//                    return lookupKeyValueMap;
//            }
//            




    
    public static void main(String[] args){
        OIMLdapConnect oimLdapConnection= new OIMLdapConnect();
        try {
              oimLdapConnection.createLDAPObject("maktestUser2022");
              oimLdapConnection.assingGrouptoUser("maktestUser2022", "CN=1231.0N Situation-Book,OU=Groups,DC=SH-Test,DC=org");
              oimLdapConnection.assingGrouptoUser("maktestUser2022", "CN=1231.2 Diminutive Room-Editor,OU=Groups,DC=SH-Test,DC=org");
              oimLdapConnection.assingGrouptoUser("maktestUser2022", "CN=1231.2N Eaton-Editor,OU=Groups,DC=SH-Test,DC=org");
              oimLdapConnection.assingGrouptoUser("maktestUser2022", "CN=1231.2N Montcalm-Editor,OU=Groups,DC=SH-Test,DC=org");
           // oimLdapConnection.getITResourceParameter("SH Active Directory");
           // oimLdapConnection.ldapConnect();
            //oimLdapConnection.findManagersFQDN("AALANNN");
           //oimLdapConnection. getUserDn ("AALANNN");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    
}
