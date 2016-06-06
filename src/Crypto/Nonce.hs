-- | Usage of this module is very simple.  Here is a sample GHCi run:
--
-- @
-- *Crypto.Nonce> g <- new
-- *Crypto.Nonce> nonce128 g
-- \"c\\164\\252\\162f\\207\\245\\ESC`\\180p\\DC4\\234\\223QP\"
-- *Crypto.Nonce> nonce128 g
-- \"\\203C\\190\\138aI\\158\\194\\146\\&7\\208\\&7\\ETX0\\f\\229\"
-- *Crypto.Nonce> nonce128url g
-- \"3RP-iEFT-6NrpCMsxigondMC\"
-- *Crypto.Nonce> nonce128url g
-- \"MVZH3Gi5zSKXJY-_qdtznxla\"
-- *Crypto.Nonce> nonce128url g
-- \"3f3cVNfuZT62-uGco1CBThci\"
-- *Crypto.Nonce> nonce128urlT g
-- \"iGMJyrRkw2QMp09SRy59s4Jx\"
-- *Crypto.Nonce> nonce128urlT g
-- \"WsHs0KwYiex3tsqQZ8b0119_\"
-- *Crypto.Nonce> nonce128urlT g
-- \"JWkLSX7qSFGu1Q3PHuExwurF\"
-- @
--
-- The functions that generate nonces are not pure on purpose,
-- since that makes it a lot harder to reuse the same nonce.
module Crypto.Nonce
  ( Generator
  , new
  , nonce128
  , nonce128url
  , nonce128urlT
  ) where

import Control.Monad (liftM)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Crypto.Random
import Data.Tuple (swap)
import Data.Typeable (Typeable)

import qualified Data.ByteString as B
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.IORef as I
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE


-- | An encapsulated nonce generator.
data Generator =
  G (I.IORef SystemDRG)
  deriving (Typeable)

instance Show Generator where
  show _ = "<NonceGenerator>"


-- | Create a new nonce generator using the system entropy.
new :: MonadIO m => m Generator
new = liftM G . liftIO $ getSystemDRG >>= I.newIORef


-- | (Internal) Generate the given number of bytes from the DRG.
genBytes :: MonadIO m => Int -> Generator -> m B.ByteString
genBytes n (G v) = liftIO $ I.atomicModifyIORef v $ swap . randomBytesGenerate n


-- | Generate a 128 bit nonce as a 'B.ByteString' of 16 bytes.
-- Each byte may have any value from @0@ to @255@.
nonce128 :: MonadIO m => Generator -> m B.ByteString
nonce128 = genBytes 16


-- | Generate a 128 bit nonce as a 'B.ByteString' of 24 bytes.
-- Each byte is either a letter (upper or lowercase), a digit, a
-- dash (@-@) or an underscore (@_@), which is the set of
-- characters from the base64url encoding.  In order to avoid any
-- issues with padding, the generated nonce actually has 144 bits.
nonce128url :: MonadIO m => Generator -> m B.ByteString
nonce128url = liftM B64URL.encode . genBytes 18


-- | Same as 'nonce128url', but returns its result as 'T.Text'
-- instead.
nonce128urlT :: MonadIO m => Generator -> m T.Text
nonce128urlT = liftM TE.decodeUtf8 . nonce128url
