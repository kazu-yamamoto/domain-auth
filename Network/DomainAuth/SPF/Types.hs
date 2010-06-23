module Network.DomainAuth.SPF.Types where

import Data.IP
import Network.DNS (Domain)

----------------------------------------------------------------

-- See DAResult in Network.DomainAuth.Types
data Qualifier = Q_Pass | Q_HardFail | Q_Softfail | Q_Neutral
                 deriving (Eq,Enum,Bounded,Show)

-- Depends on Qualifier
qualifierSymbol :: String
qualifierSymbol = "+-~?"

data SPF = SPF_IPv4Range Qualifier (AddrRange IPv4)
         | SPF_IPv6Range Qualifier (AddrRange IPv6)
         | SPF_Address   Qualifier (Maybe Domain) (Int,Int)
         | SPF_MX        Qualifier (Maybe Domain) (Int,Int)
         | SPF_Include   Qualifier Domain
         | SPF_All       Qualifier
         | SPF_Redirect            Domain
           deriving Show

----------------------------------------------------------------

data SpfSeq = SS_All        Qualifier
            | SS_IPv4Range  Qualifier (AddrRange IPv4)
            | SS_IPv6Range  Qualifier (AddrRange IPv6)
            | SS_IPv4Ranges Qualifier [AddrRange IPv4]
            | SS_IPv6Ranges Qualifier [AddrRange IPv6]
            | SS_IF_Pass    Qualifier [IO SpfSeq]
            | SS_SpfSeq               [IO SpfSeq]
