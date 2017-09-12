{-# LANGUAGE OverloadedStrings #-}

-- | Purported Responsible Domain, RFC 4407.

module Network.DomainAuth.PRD.PRD (
    PRD
  , initialPRD, pushPRD
  , decidePRD, decideFrom
  ) where

import Control.Monad
import qualified Data.ByteString.Char8 as BS
import Data.Char
import Data.List (foldl')
import Network.DNS (Domain)
import Network.DomainAuth.Mail
import Network.DomainAuth.PRD.Domain

----------------------------------------------------------------

type HD = [(CanonFieldKey,RawFieldValue)]

data DST = DST_Zero | DST_Invalid | DST_Valid Domain deriving (Eq, Show)

-- | Abstract type for context to decide PRD(purported responsible domain)
--   according to RFC 4407.
data PRD = PRD {
    praFrom         :: DST
  , praSender       :: DST
  , praResentFrom   :: DST
  , praResentSender :: DST
  , praHeader       :: HD
  } deriving Show

-- | Initial context of PRD.
initialPRD :: PRD
initialPRD = PRD {
    praFrom         = DST_Zero
  , praSender       = DST_Zero
  , praResentFrom   = DST_Zero
  , praResentSender = DST_Zero
  , praHeader       = []
  }

----------------------------------------------------------------

-- | Pushing a field key and its value in to the PRD context.
pushPRD :: RawFieldKey -> RawFieldValue -> PRD -> PRD
pushPRD key val ctx = case ckey of
    "from"          -> pushFrom ctx' jdom
    "sender"        -> pushSender ctx' jdom
    "resent-from"   -> pushResentFrom ctx' jdom
    "resent-sender" -> pushResentSender ctx' jdom
    _               -> ctx'
  where
    ckey = BS.map toLower key
    jdom = extractDomain val
    ctx' = ctx { praHeader = (ckey,val) : praHeader ctx }

-- | Deciding PRD from the RPD context.
--
-- >>> let maddr1 = "alice@alice.example.jp"
-- >>> let maddr2 = "bob@bob.example.jp"
-- >>> let maddr3 = "chris@chris.example.jp"
-- >>> let maddr4 = "dave@dave.example.jp"
-- >>> decidePRD (pushPRD "from" "alice@alice.example.jp" initialPRD)
-- Just "alice.example.jp"
-- >>> :{
-- decidePRD (pushPRD "from" maddr1
--          $ pushPRD "from" maddr1 initialPRD)
-- :}
-- Nothing
--
-- >>> :{
-- decidePRD (pushPRD "sender" maddr2
--          $ pushPRD "from" maddr1
--          $ pushPRD "from" maddr1 initialPRD)
-- :}
-- Just "bob.example.jp"
--
-- >>> :{
-- decidePRD (pushPRD "sender" maddr2
--          $ pushPRD "sender" maddr2
--          $ pushPRD "from" maddr1
--          $ pushPRD "from" maddr1 initialPRD)
-- :}
-- Nothing
--
-- >>> :{
-- decidePRD (pushPRD "resent-from" maddr3
--          $ pushPRD "sender" maddr2
--          $ pushPRD "sender" maddr2
--          $ pushPRD "from" maddr1
--          $ pushPRD "from" maddr1 initialPRD)
-- :}
-- Just "chris.example.jp"
--
-- >>> :{
-- decidePRD (pushPRD "resent-sender" maddr4
--           $ pushPRD "resent-from" maddr3
--           $ pushPRD "sender" maddr2
--           $ pushPRD "sender" maddr2
--           $ pushPRD "from" maddr1
--           $ pushPRD "from" maddr1 initialPRD)
-- :}
-- Just "dave.example.jp"
--
-- >>> :{
-- decidePRD (pushPRD "resent-sender" maddr4
--          $ pushPRD "resent-from" maddr3
--          $ pushPRD "sender" maddr2
--          $ pushPRD "received" "dummy"
--          $ pushPRD "from" maddr1 initialPRD)
-- :}
-- Just "dave.example.jp"
--
-- >>> :{
-- decidePRD (pushPRD "resent-sender" maddr4
--          $ pushPRD "received" "dummy"
--          $ pushPRD "resent-from" maddr3
--          $ pushPRD "sender" maddr2
--          $ pushPRD "from" maddr1 initialPRD)
-- :}
-- Just "chris.example.jp"
--
-- >>> :{
-- decidePRD (pushPRD "received" "dummy"
--           $ pushPRD "resent-sender" maddr4
--           $ pushPRD "resent-from" maddr3
--           $ pushPRD "sender" maddr2
--           $ pushPRD "from" maddr1 initialPRD)
-- :}
-- Just "dave.example.jp"

decidePRD :: PRD -> Maybe Domain
decidePRD ctx =
    let jds = [ praResentSender ctx
              , praResentFrom ctx
              , praSender ctx
              , praFrom ctx
              ]
    in foldl' mplus mzero $ map toMaybe jds

-- | Taking the value of From: from the RPD context.
--
-- >>> decideFrom (pushPRD "from" "alice@alice.example.jp" initialPRD)
-- Just "alice.example.jp"
decideFrom :: PRD -> Maybe Domain
decideFrom = toMaybe . praFrom

toMaybe :: DST -> Maybe Domain
toMaybe (DST_Valid d) = Just d
toMaybe _             = Nothing

----------------------------------------------------------------

pushFrom :: PRD -> Maybe Domain -> PRD
pushFrom ctx Nothing    = ctx { praFrom = DST_Invalid }
pushFrom ctx (Just dom) = ctx { praFrom = from }
  where
    from = case praFrom ctx of
        DST_Zero -> DST_Valid dom
        _        -> DST_Invalid

pushSender :: PRD -> Maybe Domain -> PRD
pushSender ctx Nothing    = ctx { praSender = DST_Invalid }
pushSender ctx (Just dom) = ctx { praSender = sender }
  where
    sender = case praSender ctx of
        DST_Zero -> DST_Valid dom
        _        -> DST_Invalid

pushResentFrom :: PRD -> Maybe Domain -> PRD
pushResentFrom ctx Nothing    = ctx { praResentFrom = DST_Invalid }
pushResentFrom ctx (Just dom) = ctx { praResentFrom = rfrom }
  where
    rfrom = case praResentFrom ctx of
        DST_Zero    -> DST_Valid dom
        DST_Valid d -> DST_Valid d
        DST_Invalid -> DST_Invalid

pushResentSender :: PRD -> Maybe Domain -> PRD
pushResentSender ctx Nothing        = ctx { praResentSender = DST_Invalid }
pushResentSender ctx (Just dom)
    | praResentFrom ctx == DST_Zero = ctx { praResentSender = rsender }
    | isFirstBlock (praHeader ctx)  = ctx { praResentSender = DST_Valid dom }
    | otherwise                     = ctx { praResentSender = DST_Invalid }
  where
    rsender = case praResentSender ctx of
        DST_Zero    -> DST_Valid dom
        DST_Valid d -> DST_Valid d
        DST_Invalid -> DST_Invalid

isFirstBlock :: HD -> Bool
isFirstBlock hdr = all rr . takeWhile end $ hdr
  where
    end = (/= "resent-from") . fst
    rr  = (`notElem` ["received", "return-path"]) . fst
