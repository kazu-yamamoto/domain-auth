{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Pubkey.Der (
    decode
  , Class (..)
  , TLV (..)
  ) where

import Control.Monad
import Data.Binary.Get
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL

----------------------------------------------------------------

data TLV = Term
         | Prim { cls :: Class
                , tag :: Tag
                , siz :: Size
                , cnt :: ByteString
                }
         | Cons { cls :: Class
                , tag :: Tag
                , siz :: Size
                , tlv :: [TLV]
                }
         deriving Show

data Class = Univ | Appl | Cont | Priv deriving (Show, Eq, Enum)
type Tag  = Int
type Size = Int

----------------------------------------------------------------

decode :: BL.ByteString -> TLV
decode = runGet der

----------------------------------------------------------------

der :: Get TLV
der = do
    first <- nonZero
    let clss = getClass first
        cons = getConstructor first
    tg <- getTag first
    len <- singleLength
    if cons
       then construct clss tg len
       else primitive clss tg len

primitive :: Class -> Tag -> Int -> Get TLV
primitive clss tg len = Prim clss tg len <$> getByteString (fromIntegral len)

construct :: Class -> Tag -> Int -> Get TLV
construct = definite
    {-
    if len == indefiniteMark
    then indefinite clss tg len
    else definite clss tg len
    -}

definite :: Class -> Tag -> Int -> Get TLV
definite clss tg len = do
    start <- fromIntegral <$> bytesRead
    let end = start + len
    Cons clss tg len <$> withinLimit end []
  where
    withinLimit end ps = do
        p <- der
        end2 <- fromIntegral <$> bytesRead -- xxx
        if end2 == end
           then return (ps ++ [p])
           else withinLimit end (ps ++ [p])

{-
terminate :: Get TLV
terminate = Term <$ (zer0 >> zer0)

indefinite :: Class -> Tag -> Int -> Get TLV
indefinite clss tg len = Cons clss tg len <$> (many der <* terminate)
-}

getClass :: Int -> Class
getClass first = toEnum (shift (first .&. classMask) (- classShift)) :: Class

getConstructor :: Int -> Bool
getConstructor first = first .&. consFlag == consFlag

getTag :: Int -> Get Int
getTag first = if tg == tagMask
               then multiTag 0
               else return tg
  where
    tg = first .&. tagMask

multiTag :: Int -> Get Int
multiTag len = do
    i <- anyInt
    if (i .&. tagEnd) == 0
       then return (incTag len i)
       else multiTag (incTag len i)

incTag :: Int -> Int -> Int
incTag len i = len * 128 + (i .&. tagLenMask)

singleLength :: Get Int
singleLength = do
    second <- anyInt
    let multi = getMulti second
        len = getLen second
    if multi
       then definiteLength len
       else return len

getMulti :: Int -> Bool
getMulti second = second .&. lenFlag == lenFlag

getLen :: Int -> Int
getLen second = second .&. lenMask

definiteLength :: Int -> Get Int
definiteLength bytes = if bytes == 0
                       then return indefiniteMark
                       else multiLength 0 bytes

multiLength :: Int -> Int -> Get Int
multiLength len bytes = do
    i <- anyInt
    if bytes == 1
       then return (incLen len i)
       else multiLength (incLen len i) (bytes - 1)

incLen :: Int -> Int -> Int
incLen len i = len * 256 + i

----------------------------------------------------------------

anyInt :: Get Int
anyInt = fromIntegral <$> getWord8

nonZero :: Get Int
nonZero = do
    n <- anyInt
    when (n == 0) (error "nonZero")
    return n

{-
zer0 :: Get Int
zer0 = do
    n <- anyInt
    when (n /= 0) (error "zer0")
    return n
-}

----------------------------------------------------------------

classMask :: Int
classMask  = 0xc0
classShift :: Int
classShift = 6
consFlag :: Int
consFlag   = 0x20

tagMask :: Int
tagMask    = 0x1f
tagEnd :: Int
tagEnd     = 0x80
tagLenMask :: Int
tagLenMask = 0x7f

lenFlag :: Int
lenFlag    = 0x80
lenMask :: Int
lenMask    = 0x7f

indefiniteMark :: Int
indefiniteMark = -1 -- xxx
