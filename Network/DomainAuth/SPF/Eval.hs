module Network.DomainAuth.SPF.Eval (evalSPF, Limit(..), defaultLimit) where

import Control.Applicative
import Data.IORef
import Data.IP
import Data.Maybe
import Network.DomainAuth.SPF.Types
import Network.DomainAuth.Types

{-|
  Limit for SPF authentication.
-}
data Limit = Limit {
    -- | How many \"redirect\"/\"include\" should be followed.
    limit :: Int
    -- | Ignoring IPv4 range whose mask length is shorter than this.
  , ipv4_masklen :: Int
    -- | Ignoring IPv6 range whose mask length is shorter than this.
  , ipv6_masklen :: Int
    -- | Whether or not \"+all\" is rejected.
  , reject_plus_all :: Bool
  }

{-|
  Default 'Limit'. 'limit' is 10. 'ipv4_masklen' is 16.
  'ipv6_masklen' is 48. 'reject_plus_all' is 'True'.
-}
defaultLimit :: Limit
defaultLimit = Limit {
    limit = 10
  , ipv4_masklen = 16
  , ipv6_masklen = 48
  , reject_plus_all = True
  }

----------------------------------------------------------------

evalSPF :: Limit -> IP -> [IO SpfSeq] -> IO DAResult
evalSPF lim ip ss = do
    ref <- newIORef (0 :: Int)
    fromJust <$> evalspf ref lim ip ss

----------------------------------------------------------------

evalspf :: IORef Int -> Limit -> IP -> [IO SpfSeq] -> IO (Maybe DAResult)
evalspf _ _ _ [] = return (Just DANeutral) -- default result
evalspf ref lim ip (s:ss) = do
    cnt <- readIORef ref
    if cnt > limit lim
       then return (Just DAPermError) -- reached the limit
       else do
           mres <- eval ref lim ip s
           case mres of
               Nothing  -> evalspf ref lim ip ss
               res      -> return res

----------------------------------------------------------------
{-
Follow N of redirect/include. But the last one is not
evaluated.
-}

eval :: IORef Int -> Limit -> IP -> IO SpfSeq -> IO (Maybe DAResult)
eval ref lim ip is = do
    cnt <- readIORef ref
    s <- is
    case s of
      SS_All q -> if q == Q_Pass && reject_plus_all lim
                  then result DAPermError
                  else ret q
      SS_IPv4Range q ipr
           | nastyMask4 lim ipr        -> result DAPermError
           | ipv4 ip `isMatchedTo` ipr -> ret q
           | otherwise                 -> continue
      SS_IPv4Ranges q iprs
           | any (nastyMask4 lim) iprs        -> result DAPermError
           | any (ipv4 ip `isMatchedTo`) iprs -> ret q
           | otherwise                        -> continue
      SS_IPv6Range q ipr
           | nastyMask6 lim ipr        -> result DAPermError
           | ipv6 ip `isMatchedTo` ipr -> ret q
           | otherwise                 -> continue
      SS_IPv6Ranges q iprs
           | any (nastyMask6 lim) iprs        -> result DAPermError
           | any (ipv6 ip `isMatchedTo`) iprs -> ret q
           | otherwise                        -> continue
      SS_IF_Pass q ss -> do
          writeIORef ref (cnt + 1)
          r <- evalspf ref lim ip ss
          if r == Just DAPass
            then ret q
            else continue
      SS_SpfSeq ss -> do
          writeIORef ref (cnt + 1)
          evalspf ref lim ip ss
  where
    ret = return . Just . toEnum . fromEnum
    result = return . Just
    continue = return Nothing
    nastyMask4 st ipr = mlen ipr < ipv4_masklen st
    nastyMask6 st ipr = mlen ipr < ipv6_masklen st
