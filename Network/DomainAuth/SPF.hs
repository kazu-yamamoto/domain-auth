-- | A library for SPF(<http://www.ietf.org/rfc/rfc4408>)
--   and Sender-ID(<http://www.ietf.org/rfc/rfc4406>).

module Network.DomainAuth.SPF (
    runSPF
  , Limit(..)
  , defaultLimit
  ) where

import Control.Exception as E
import Data.IP
import Network.DNS (Domain, Resolver)
import Network.DomainAuth.SPF.Eval
import Network.DomainAuth.SPF.Resolver
import Network.DomainAuth.Types
import System.IO.Error

-- $setup
-- >>> import Network.DNS

-- | Process SPF authentication. 'IP' is an IP address of an SMTP peer.
--   If 'Domain' is specified from SMTP MAIL FROM, authentication is
--   based on SPF. If 'Domain' is specified from the From field of mail
--   header, authentication is based on SenderID. If condition reaches
--   'Limit', 'SpfPermError' is returned.
--
-- >>> rs <- makeResolvSeed defaultResolvConf
-- >>> withResolver rs $ \rslv -> runSPF defaultLimit rslv "mew.org" "210.130.207.72"
-- pass
-- >>> withResolver rs $ \rslv -> runSPF defaultLimit rslv "example.org" "192.0.2.1"
-- hardfail
-- >>> withResolver rs $ \rslv -> runSPF defaultLimit rslv "iij.ad.jp" "2001:240:bb42:8010::1:126"
-- pass

runSPF :: Limit -> Resolver -> Domain -> IP -> IO DAResult
runSPF lim resolver dom ip =
    (resolveSPF resolver dom ip >>= evalSPF lim ip) `E.catch` spfErrorHandle

spfErrorHandle :: IOError -> IO DAResult
spfErrorHandle e = case ioeGetErrorString e of
                     "TempError" -> return DATempError
                     "PermError" -> return DAPermError
                     _           -> return DANone
