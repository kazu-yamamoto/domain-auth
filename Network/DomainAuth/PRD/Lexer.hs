{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.PRD.Lexer (
    structured
  ) where

import Control.Applicative
import Data.Attoparsec.ByteString (Parser)
import qualified Data.Attoparsec.ByteString as P
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Char8 ()
import Data.Word8

----------------------------------------------------------------

concatSpace :: [ByteString] -> ByteString
concatSpace = BS.intercalate " "

----------------------------------------------------------------

skipChar :: Word8 -> Parser ()
skipChar c = () <$ P.word8 c

skipWsp :: Parser ()
skipWsp = P.skipWhile $ P.inClass " \t\n"

----------------------------------------------------------------

-- |
--
-- >>> P.parseOnly structured "From: Kazu Yamamoto (=?iso-2022-jp?B?GyRCOzNLXE9CSScbKEI=?=)\n <kazu@example.net>"
-- Right ["From",":","Kazu","Yamamoto","<","kazu","@","example",".","net",">"]
-- >>> P.parseOnly structured "To:A Group(Some people)\n      :Chris Jones <c@(Chris's host.)public.example>,\n          joe@example.org,\n   John <jdoe@one.test> (my dear friend); (the end of the group)\n"
-- Right ["To",":","A","Group",":","Chris","Jones","<","c","@","public",".","example",">",",","joe","@","example",".","org",",","John","<","jdoe","@","one",".","test",">",";"]
-- >>> P.parseOnly structured "Date: Thu,\n      13\n        Feb\n          1969\n      23:32\n               -0330 (Newfoundland Time)\n"
-- Right ["Date",":","Thu",",","13","Feb","1969","23",":","32","-0330"]
-- >>> P.parseOnly structured "From: Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>\n"
-- Right ["From",":","Pete","<","pete","@","silly",".","test",">"]
structured :: Parser [ByteString]
structured = removeComments <$> many (P.choice choices)
  where
    removeComments = filter (/="")
    choices = [specials,quotedString,domainLiteral,atom,comment]

specials :: Parser ByteString
specials = specialChar <* skipWsp
  where
    -- removing "()[]\\\""
    specialChar = BS.singleton <$> word8in "<>:;@=,."

----------------------------------------------------------------

atom :: Parser ByteString
atom = atext <* skipWsp
  where
    atext = P.takeWhile1 $ P.inClass "0-9a-zA-Z!#$%&'*+/=?^_`{|}~-"

----------------------------------------------------------------

domainLiteral :: Parser ByteString
domainLiteral = do
    skipChar _bracketleft
    ds <- many (dtext <* skipWsp)
    skipChar _bracketright
    skipWsp
    return $ concatSpace ds
  where
      dtext = P.takeWhile1 $ P.inClass "!-Z^-~"

----------------------------------------------------------------

word8in :: String -> Parser Word8
word8in = P.satisfy . P.inClass

qtext :: Parser Word8
qtext = word8in "!#-[]-~"

qcontent :: Parser Word8
qcontent = qtext <|> quoted_pair

quotedString :: Parser ByteString
quotedString = do
    skipChar _quotedbl
    skipWsp
    qs <- map BS.pack <$> many (some qcontent <* skipWsp)
    skipChar _quotedbl
    skipWsp
    return $ concatSpace qs

----------------------------------------------------------------

quoted_pair :: Parser Word8
quoted_pair = skipChar _backslash >> word8in "!-~ \t\n" -- vchar ++ wsp

----------------------------------------------------------------

ctext :: Parser Word8
ctext = word8in "!-'*-[]-~"

ccontent :: Parser ()
ccontent = () <$ some (ctext <|> quoted_pair)

comment' :: Parser ()
comment' = do
    skipChar _parenleft
    skipWsp
    _ <- many ((ccontent <|> comment') <* skipWsp)
    skipChar _parenright
    skipWsp
    return ()

comment :: Parser ByteString
comment = "" <$ comment'
