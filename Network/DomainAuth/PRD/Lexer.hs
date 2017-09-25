module Network.DomainAuth.PRD.Lexer (
    structured
  ) where

import Text.Appar.ByteString

----------------------------------------------------------------

concatSpace :: [String] -> String
concatSpace = unwords

----------------------------------------------------------------

skipChar :: Char -> Parser ()
skipChar c = () <$ char c

skipWsp :: Parser ()
skipWsp = skipMany $ oneOf " \t\n"

----------------------------------------------------------------

-- |
--
-- >>> parse structured "From: Kazu Yamamoto (=?iso-2022-jp?B?GyRCOzNLXE9CSScbKEI=?=)\n <kazu@example.net>"
-- Just ["From",":","Kazu","Yamamoto","<","kazu","@","example",".","net",">"]
-- >>> parse structured "To:A Group(Some people)\n      :Chris Jones <c@(Chris's host.)public.example>,\n          joe@example.org,\n   John <jdoe@one.test> (my dear friend); (the end of the group)\n"
-- Just ["To",":","A","Group",":","Chris","Jones","<","c","@","public",".","example",">",",","joe","@","example",".","org",",","John","<","jdoe","@","one",".","test",">",";"]
-- >>> parse structured "Date: Thu,\n      13\n        Feb\n          1969\n      23:32\n               -0330 (Newfoundland Time)\n"
-- Just ["Date",":","Thu",",","13","Feb","1969","23",":","32","-0330"]
-- >>> parse structured "From: Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>\n"
-- Just ["From",":","Pete","<","pete","@","silly",".","test",">"]
structured :: Parser [String]
structured = removeComments <$> many (choice choices)
  where
    removeComments = filter (/="")
    choices = [specials,quotedString,domainLiteral,atom,comment]

specials :: Parser String
specials = toStr <$> (specialChar <* skipWsp)
  where
    -- removing "()[]\\\""
    specialChar = oneOf "<>:;@=,."
    toStr c = [c]

----------------------------------------------------------------

atext :: Parser Char
atext = alphaNum <|> oneOf "!#$%&'*+-/=?^_`{|}~"

atom :: Parser String
atom = some atext <* skipWsp

----------------------------------------------------------------

dtext :: Parser Char
dtext = oneOf $ ['!' .. 'Z'] ++ ['^' .. '~']

domainLiteral :: Parser String
domainLiteral = do
    skipChar '['
    ds <- many (some dtext <* skipWsp)
    skipChar ']'
    skipWsp
    return (concatSpace ds)

----------------------------------------------------------------

qtext :: Parser Char
qtext = oneOf $ "!" ++ ['#' .. '['] ++ [']' .. '~']

qcontent :: Parser Char
qcontent = qtext <|> quoted_pair

quotedString :: Parser String
quotedString = do
    skipChar '"'
    skipWsp
    qs <- many (some qcontent <* skipWsp)
    skipChar '"'
    skipWsp
    return (concatSpace qs)

----------------------------------------------------------------

vchar :: Parser Char
vchar = oneOf ['!'..'~']

wsp :: Parser Char
wsp = oneOf " \t\n"

quoted_pair :: Parser Char
quoted_pair = skipChar '\\' >> (vchar <|> wsp)

----------------------------------------------------------------

ctext :: Parser Char
ctext = oneOf $ ['!' .. '\''] ++ ['*' .. '['] ++ [']' .. '~']

ccontent :: Parser ()
ccontent = () <$ some (ctext <|> quoted_pair)

comment' :: Parser ()
comment' = do
    skipChar '('
    skipWsp
    _ <- many ((ccontent <|> comment') <* skipWsp)
    skipChar ')'
    skipWsp
    return ()

comment :: Parser String
comment = "" <$ comment'
