module Network.DomainAuth.PRD.Lexer (
    structured
  ) where

import Text.Appar.LazyByteString

----------------------------------------------------------------

concatSpace :: [String] -> String
concatSpace = unwords

----------------------------------------------------------------

skipChar :: Char -> Parser ()
skipChar c = () <$ char c

wsp :: Parser Char
wsp = oneOf " \t\n"

----------------------------------------------------------------

structured :: Parser [String]
structured = removeComments <$> many (choice choices)
  where
    removeComments = filter (/="")
    choices = [specials,quotedString,domainLiteral,atom,comment]

specials :: Parser String
specials = toStr <$> (specialChar <* skipMany wsp)
  where
    -- removing "()[]\\\""
    specialChar = oneOf "<>:;@=,."
    toStr c = [c]

----------------------------------------------------------------

atext :: Parser Char
atext = alphaNum <|> oneOf "!#$%&'*+-/=?^_`{|}~"

atom :: Parser String
atom = some atext <* skipMany wsp

----------------------------------------------------------------

dtext :: Parser Char
dtext = oneOf $ ['!' .. 'Z'] ++ ['^' .. '~']

domainLiteral :: Parser String
domainLiteral = do
    skipChar '['
    ds <- many (some dtext <* skipMany wsp)
    skipChar ']'
    skipMany wsp
    return (concatSpace ds)

----------------------------------------------------------------

qtext :: Parser Char
qtext = oneOf $ "!" ++ ['#' .. '['] ++ [']' .. '~']

qcontent :: Parser Char
qcontent = qtext <|> quoted_pair

quotedString :: Parser String
quotedString = do
    skipChar '"'
    skipMany wsp
    qs <- many (some qcontent <* skipMany wsp)
    skipChar '"'
    skipMany wsp
    return (concatSpace qs)

----------------------------------------------------------------

vchar :: Parser Char
vchar = oneOf ['!'..'~']

quoted_pair :: Parser Char
quoted_pair = skipChar '\\' >> (vchar <|> wsp)

----------------------------------------------------------------

ctext :: Parser Char
ctext = oneOf $ ['!' .. '\''] ++ ['*' .. '['] ++ [']' .. '~']

ccontent :: Parser String
ccontent = some (ctext <|> quoted_pair)

comment' :: Parser String
comment' = do
    skipChar '('
    skipMany wsp
    cs <- many ((ccontent <|> comment') <* skipMany wsp)
    skipChar ')'
    skipMany wsp
    return (concatSpace cs)

comment :: Parser String
comment = "" <$ comment'
