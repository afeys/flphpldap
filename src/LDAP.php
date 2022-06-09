<?php

namespace FL;

class LDAP {

    protected $host;
    protected $port = 389;
    protected $baseDN;
    protected $user;   // user with read access to ldap tree
    protected $password;

    /**
     * Helper function to the constructor.
     * This allows chaining multiple commands in one line:
     * $passwordok = LDAP::getInstance()->->setHost(Config::LDAPHost)->setPort(Config::LDAPPort)->setBaseDN(Config::LDAPBaseDN)->setUser(Config::LDAPUser)->setPassword(Config::LDAPPwd)->validateUserLogin($loginid, $password);
     * getInstance takes no parameters in this case.
     * @return object the LDAP instance
     */
    public static function getInstance() {
        static $instance;
        if (!isset($instance)) {
            $c = __CLASS__;
            $instance = new $c;
        }
        return $instance;
    }

    // --------------------------------------------------------------------------------------//
    // __ FUNCTIONS                                                                      //
    // --------------------------------------------------------------------------------------//

    /**
     * Initializes a LDAP instance. 
     */
    function __construct() {
        
    }

    public function setHost($host) {
        $this->host = $host;
        return $this;
    }

    public function setPort($port) {
        $this->port = $port;
        return $this;
    }

    public function setUser($user) {
        $this->user = $user;
        return $this;
    }

    public function setPassword($password) {
        $this->password = $password;
        return $this;
    }

    public function setBaseDN($basedn) {
        $this->baseDN = $basedn;
        return $this;
    }

    public function queryLDAP($query, $justshow = null) {
        $returnvalue = "";
        $connect = ldap_connect($this->host, $this->port);
        if ($connect) {
            ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);
            $bind = ldap_bind($connect, $this->user, $this->password);
            if ($bind) {
                if ($justshow !== null) {
                    $result = ldap_search($connect, $this->baseDN, $query, $justshow);
                } else {
                    $result = ldap_search($connect, $this->baseDN, $query);
                }
                $entries = ldap_get_entries($connect, $result);
                $returnvalue = $entries;
                ldap_unbind($connect);
            }
        }
        return $returnvalue;
    }

    public function validateUserLogin($loginid, $password) {
        $returnvalue = false;
        $user = $this->getUserCN($loginid);
        if ($user !== "" && $user !== null) {
            $connect = ldap_connect($this->host, $this->port);
            if ($connect) {
                // the following lines are required to search Active Directory
                ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
                ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);
                $bind = @ldap_bind($connect, $user, $password);
                if ($bind) {
                    ldap_unbind($connect);
                    $returnvalue = true;
                }
            }
        }
        return $returnvalue;
    }

    public function getUserCN($loginid) {
        $returnvalue = "";
        $connect = ldap_connect($this->host, $this->port);
        if ($connect) {
            ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);
            $bind = ldap_bind($connect, $this->user, $this->password);
            if ($bind) {
                $result = ldap_search($connect, $this->baseDN, "(sAMAccountName=" . $this->LDAPQuote($loginid) . ")");
                $entries = ldap_get_entries($connect, $result);
                if (is_array($entries)) {
                    if ($entries['count'] > 0) {
                        if (is_array($entries[0]["distinguishedname"])) {
                            if (count($entries[0]["distinguishedname"]) > 0) {
                                $returnvalue = $entries[0]["distinguishedname"][0];
                            }
                        }
                    }
                }
                ldap_unbind($connect);
            }
        }
        return $returnvalue;
    }

    public function getUserMail($loginid) {
        $returnvalue = "";
        $connect = ldap_connect($this->host, $this->port);
        if ($connect) {
            ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);
            $bind = ldap_bind($connect, $this->user, $this->password);
            if ($bind) {
                $result = ldap_search($connect, $this->baseDN, "(sAMAccountName=" . $this->LDAPQuote($loginid) . ")");
                $entries = ldap_get_entries($connect, $result);
                $returnvalue = $entries[0]["mail"][0];
                ldap_unbind($connect);
            }
        }
        return $returnvalue;
    }

    protected function LDAPQuote($string) {
        return str_replace(array('\\', ' ', '*', '(', ')'), array('\\5c', '\\20', '\\2a', '\\28', '\\29'), $string);
    }

}
