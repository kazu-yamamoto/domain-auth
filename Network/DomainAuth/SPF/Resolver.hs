{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.SPF.Resolver (resolveSPF) where

import Control.Applicative
import Control.Monad
import Data.IP
import qualified Data.ByteString.Char8 as BS
import Data.Maybe
import Network.DNS
import Network.DomainAuth.SPF.Parser
import Network.DomainAuth.SPF.Types

----------------------------------------------------------------

resolveSPF :: Resolver -> Domain -> IP -> IO [IO SpfSeq]
resolveSPF resolver dom ip = do
    jrc <- lookupTXT resolver dom
    checkDNS jrc "TempError"
    let rr = getSPFRR jrc
    checkExistence rr "None"
    let jrs = parseSPF rr
    checkSyntax jrs "PermError"
    let is = filterSPFWithIP ip (fromJust jrs)
    return $ map (toSpfSeq resolver dom ip) is
  where
    getSPFRR jrc = let ts = filter ("v=spf1" `BS.isPrefixOf`) (fromJust jrc)
                   in if null ts then "" else head ts
    checkSyntax rs estr = when (isNothing rs) (fail estr)
    checkExistence rr estr = when (BS.null rr) (fail estr)

----------------------------------------------------------------

filterSPFWithIP :: IP -> [SPF] -> [SPF]
filterSPFWithIP (IPv4 _) spfs = filter exceptIPv4 spfs
filterSPFWithIP (IPv6 _) spfs = filter exceptIPv6 spfs

exceptIPv4 :: SPF -> Bool
exceptIPv4 (SPF_IPv6Range _ _) = False
exceptIPv4 _                   = True

exceptIPv6 :: SPF -> Bool
exceptIPv6 (SPF_IPv4Range _ _) = False
exceptIPv6 _                   = True

----------------------------------------------------------------

toSpfSeq :: Resolver -> Domain -> IP -> SPF -> IO SpfSeq
toSpfSeq _ _ _  (SPF_IPv4Range q ipr) = return $ SS_IPv4Range q ipr
toSpfSeq _ _ _  (SPF_IPv6Range q ipr) = return $ SS_IPv6Range q ipr
toSpfSeq _ _ _  (SPF_All       q)     = return $ SS_All q
toSpfSeq r _ ip (SPF_Include   q dom) = SS_IF_Pass q <$> resolveSPF r dom ip
toSpfSeq r _ ip (SPF_Redirect dom)    = SS_SpfSeq <$> resolveSPF r dom ip

toSpfSeq r dom (IPv4 _) (SPF_MX q Nothing (l4,_))
    = lookupAviaMX r dom    >>= doit4 q l4
toSpfSeq r dom (IPv6 _) (SPF_MX q Nothing (_,l6))
    = lookupAAAAviaMX r dom >>= doit6 q l6
toSpfSeq r _   (IPv4 _) (SPF_MX q (Just dom) (l4,_))
    = lookupAviaMX r dom    >>= doit4 q l4
toSpfSeq r _   (IPv6 _) (SPF_MX q (Just dom) (_,l6))
    = lookupAAAAviaMX r dom >>= doit6 q l6
toSpfSeq r dom (IPv4 _) (SPF_Address q Nothing (l4,_))
    = lookupA r dom    >>= doit4 q l4
toSpfSeq r dom (IPv6 _) (SPF_Address q Nothing (_,l6))
    = lookupAAAA r dom >>= doit6 q l6
toSpfSeq r _   (IPv4 _) (SPF_Address q (Just dom) (l4,_))
    = lookupA r dom    >>= doit4 q l4
toSpfSeq r _   (IPv6 _) (SPF_Address q (Just dom) (_,l6))
    = lookupAAAA r dom >>= doit6 q l6

doit4 :: Qualifier -> Int -> Maybe [IPv4] -> IO SpfSeq
doit4 q l4 is = do
    checkDNS is "TempError"
    return $ SS_IPv4Ranges q $ map (mkr l4) $ fromJust is
  where
    mkr = flip makeAddrRange

doit6 :: Qualifier -> Int -> Maybe [IPv6] -> IO SpfSeq
doit6 q l6 is = do
    checkDNS is "TempError"
    return $ SS_IPv6Ranges q $ map (mkr l6) $ fromJust is
  where
    mkr = flip makeAddrRange

----------------------------------------------------------------

checkDNS :: Maybe a -> String -> IO ()
checkDNS jrc estr = when (isNothing jrc) (fail estr)
