module Network.DomainAuth.Mail.XMail where

import qualified Data.ByteString.Lazy.Char8 as L
import Data.Sequence (fromList)
import Network.DomainAuth.Mail.Types
import Network.DomainAuth.Utils

----------------------------------------------------------------

-- | Type for temporary data to parse e-mail message.
data XMail = XMail {
    xmailHeader :: Header
  , xmailBody :: [RawBodyChunk]
  } deriving (Eq,Show)

-- | Initial value for 'XMail'.
initialXMail :: XMail
initialXMail = XMail [] []

-- | Storing field key and field value to the temporary data.
pushField :: RawFieldKey -> RawFieldValue -> XMail -> XMail
pushField key val xmail = xmail {
    xmailHeader = fld : xmailHeader xmail
  }
  where
    fld = Field ckey key (blines val)
    ckey = canonicalizeKey key

-- | Storing body chunk to the temporary data.
pushBody :: RawBodyChunk -> XMail -> XMail
pushBody bc xmail = xmail {
    xmailBody = bc : xmailBody xmail
  }

-- | Converting 'XMail' to 'Mail'.
finalizeMail :: XMail -> Mail
finalizeMail xmail = Mail {
    mailHeader = reverse . xmailHeader $ xmail
  , mailBody = fromList . blines . L.concat . reverse . xmailBody $ xmail
  }
