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
              deriving (Eq,Enum,Bounded,Show)
