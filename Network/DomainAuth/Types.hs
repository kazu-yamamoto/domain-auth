{-|
  Type for Message Authentication Status (<http://www.ietf.org/rfc/rfc5451.txt>).
-}

module Network.DomainAuth.Types where

----------------------------------------------------------------

{-|
  The result of domain authentication. For more information, see
  <http://www.ietf.org/rfc/rfc5451.txt>.
-}
-- See Qualifier in Network.DomainAuth.SPF.Types
data DAResult = DAPass
              | DAHardFail
              | DASoftFail
              | DANeutral
              | DAFail
              | DATempError
              | DAPermError
              | DANone
              | DAPolicy
              | DANxDomain
              | DADiscard
              | DAUnknown
              deriving (Eq,Enum,Bounded)

instance Show DAResult where
    show DAPass       = "pass"
    show DAHardFail   = "hardfail"
    show DASoftFail   = "fail"
    show DANeutral    = "neutral"
    show DAFail       = "fail"
    show DATempError  = "temperror"
    show DAPermError  = "permerror"
    show DANone       = "none"
    show DAPolicy     = "policy"
    show DANxDomain   = "nxdomain"
    show DADiscard    = "discard"
    show DAUnknown    = "unknown"
