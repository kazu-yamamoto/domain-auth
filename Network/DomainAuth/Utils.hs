{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Utils where

import qualified Data.ByteString.Lazy.Char8 as L
import Data.Int

crlf :: L.ByteString
crlf = "\r\n"

(+++) :: L.ByteString -> L.ByteString -> L.ByteString
(+++) = L.append

(!!!) :: L.ByteString -> Int64 -> Char
(!!!) = L.index
