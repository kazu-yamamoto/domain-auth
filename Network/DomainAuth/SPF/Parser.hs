module Network.DomainAuth.SPF.Parser (parseSPF) where

import Data.ByteString (ByteString)
import Data.ByteString.Char8 as BS (pack)
import Network.DNS (Domain)
import Network.DomainAuth.SPF.Types
import Prelude hiding (all)
import Text.Appar.ByteString
import Text.Read (readMaybe)

----------------------------------------------------------------

parseSPF :: ByteString -> Maybe [SPF]
parseSPF = parse spf

----------------------------------------------------------------

spaces1 :: Parser ()
spaces1 = skipSome space

----------------------------------------------------------------

spf :: Parser [SPF]
spf = do spfPrefix
         some $ do spaces1
                    -- modifier should be first since + is optional
                   modifier <|> directive

spfPrefix :: Parser ()
spfPrefix = () <$ string "v=spf1"

----------------------------------------------------------------

modifier :: Parser SPF
modifier = SPF_Redirect <$> (string "redirect=" *> domain)

directive :: Parser SPF
directive = qualifier >>= mechanism

----------------------------------------------------------------

qualifier :: Parser Qualifier
qualifier = option Q_Pass (choice quals)
    where
      func sym res = res <$ char sym
      quals = zipWith func qualifierSymbol [minBound..maxBound]

----------------------------------------------------------------

type Directive = Qualifier -> Parser SPF

mechanism :: Directive
mechanism q = choice $ map ($ q) [ip4,ip6,all,address,mx,include]

ip4 :: Directive
ip4 q = try $ do
    mip <- readMaybe <$> ip4range
    case mip of
      Nothing -> fail "ip4"
      Just ip -> return $ SPF_IPv4Range q ip
  where
    ip4range = string "ip4:" *> some (noneOf " ")

ip6 :: Directive
ip6 q = try $ do
    mip <- readMaybe <$> ip6range
    case mip of
      Nothing -> fail "ip6"
      Just ip -> return $ SPF_IPv6Range q ip
  where
    ip6range = string "ip6:" *> some (noneOf " ")

all :: Directive
all q = try $ SPF_All q <$ string "all"

address :: Directive
address q = SPF_Address q <$> (string "a" *> optionalDomain)
                          <*> optionalMask

mx :: Directive
mx q = SPF_MX q <$> (string "mx" *> optionalDomain)
                <*> optionalMask

include :: Directive
include q = SPF_Include q <$> (string "include:" *> domain)

----------------------------------------------------------------

domain :: Parser Domain
domain = BS.pack <$> some (oneOf $ ['a'..'z'] ++ ['A'..'Z'] ++ ['0'..'9'] ++ "_-.")

optionalDomain :: Parser (Maybe Domain)
optionalDomain = option Nothing (Just <$> (char ':' *> domain))

mask :: Parser Int
mask = read <$> (some . oneOf $ ['0'..'9'])

optionalMask :: Parser (Int,Int)
optionalMask = try both <|> try v4 <|> try v6 <|> none
  where
    both = (,) <$> ipv4Mask <*> ipv6Mask
    v4   = ipv4Mask >>= \l4 -> return (l4,128)
    v6   = ipv6Mask >>= \l6 -> return (32,l6)
    none = return (32,128)

ipv4Mask :: Parser Int
ipv4Mask = char '/' *> mask

ipv6Mask :: Parser Int
ipv6Mask = string "//" *> mask
