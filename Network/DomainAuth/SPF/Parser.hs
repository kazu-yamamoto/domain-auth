{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.SPF.Parser (
    parseSPF
  ) where

import Control.Applicative
import Data.Attoparsec.ByteString (Parser)
import qualified Data.Attoparsec.ByteString as P
import Data.ByteString (ByteString, ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Word8
import Network.DNS (Domain)
import Network.DomainAuth.SPF.Types
import Prelude hiding (all)
import Text.Read (readMaybe)

----------------------------------------------------------------

parseSPF :: ByteString -> Maybe [SPF]
parseSPF inp = case P.parseOnly spf inp of
  Left _    -> Nothing
  Right res -> Just res

----------------------------------------------------------------

spaces1 :: Parser ()
spaces1 = P.skipWhile isSpace

----------------------------------------------------------------

spf :: Parser [SPF]
spf = do spfPrefix
         some $ do spaces1
                    -- modifier should be first since + is optional
                   modifier <|> directive

spfPrefix :: Parser ()
spfPrefix = () <$ P.string "v=spf1"

----------------------------------------------------------------

modifier :: Parser SPF
modifier = SPF_Redirect <$> (P.string "redirect=" *> domain)

directive :: Parser SPF
directive = qualifier >>= mechanism

----------------------------------------------------------------

qualifier :: Parser Qualifier
qualifier = P.option Q_Pass (P.choice quals)
    where
      func sym res = res <$ P.word8 sym
      quals = zipWith func (BS.unpack qualifierSymbol) [minBound..maxBound]

----------------------------------------------------------------

type Directive = Qualifier -> Parser SPF

mechanism :: Directive
mechanism q = P.choice $ map ($ q) [ip4,ip6,all,address,mx,include]

ip4 :: Directive
ip4 q = P.try $ do
    mip <- readMaybe . BS8.unpack <$> ip4range
    case mip of
      Nothing -> fail "ip4"
      Just ip -> return $ SPF_IPv4Range q ip
  where
    ip4range = P.string "ip4:" *> P.takeWhile1 (P.notInClass " ")

ip6 :: Directive
ip6 q = P.try $ do
    mip <- readMaybe . BS8.unpack <$> ip6range
    case mip of
      Nothing -> fail "ip6"
      Just ip -> return $ SPF_IPv6Range q ip
  where
    ip6range = P.string "ip6:" *> P.takeWhile1 (P.notInClass " ")

all :: Directive
all q = P.try $ SPF_All q <$ P.string "all"

address :: Directive
address q = SPF_Address q <$> (P.string "a" *> optionalDomain)
                          <*> optionalMask

mx :: Directive
mx q = SPF_MX q <$> (P.string "mx" *> optionalDomain)
                <*> optionalMask

include :: Directive
include q = SPF_Include q <$> (P.string "include:" *> domain)

----------------------------------------------------------------

domain :: Parser Domain
domain = P.takeWhile1 (P.inClass "a-zA-Z0-9_.-")

optionalDomain :: Parser (Maybe Domain)
optionalDomain = P.option Nothing (Just <$> (P.word8 _colon *> domain))

mask :: Parser Int
mask = read . BS8.unpack <$> P.takeWhile1 (P.inClass "0-9")

optionalMask :: Parser (Int,Int)
optionalMask = P.try both <|> P.try v4 <|> P.try v6 <|> none
  where
    both = (,) <$> ipv4Mask <*> ipv6Mask
    v4   = ipv4Mask >>= \l4 -> return (l4,128)
    v6   = ipv6Mask >>= \l6 -> return (32,l6)
    none = return (32,128)

ipv4Mask :: Parser Int
ipv4Mask = P.word8 _slash *> mask

ipv6Mask :: Parser Int
ipv6Mask = P.string "//" *> mask
