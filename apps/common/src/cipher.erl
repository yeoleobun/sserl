-module(cipher).

-include("common.hrl").

-export([init/2, encrypt/2, decrypt/2]).

-spec init(Cipher, Pass) -> State
    when Cipher :: cipher_aead(),
         Pass :: string(),
         State :: init().
init(Cipher, Pass) ->
    #{prop_aead := true, key_length := KeySize} = crypto:cipher_info(Cipher),
    {init, Cipher, derive_key(Pass, KeySize)}.

-spec encrypt(Context, Input) -> {Output, Context}
    when Context :: init() | encrypt_ctx(),
         Input :: binary(),
         Output :: iolist().
encrypt({init, Cipher, MasterKey}, Input) ->
    Info = crypto:cipher_info(Cipher),          
    KeySize = map_get(key_length, Info),
    Salt = crypto:strong_rand_bytes(KeySize),   
    SubKey = hkdf_sha1(MasterKey, Salt, KeySize),
    Seal =
        fun(Data, Nonce) ->
           {Output, Tag} = crypto:crypto_one_time_aead(Cipher, SubKey, Nonce, Data, <<>>, true),
           {Output, Tag, inc(Nonce)}
        end,
    encrypt(Seal, ?ZERO_NONCE, Input, [Salt]);
encrypt({context, Seal, Nonce}, Input) ->
    encrypt(Seal, Nonce, Input, []).

encrypt(Seal, Nonce, <<>>, Acc) ->
    {lists:reverse(Acc), {context, Seal, Nonce}};
encrypt(Seal, Nonce, Input, Acc) ->
    Size = byte_size(Input) band ?MAX_SIZE,     % max packet size 0x3FFF
    {Cur, Rest} = split_binary(Input, Size),
    {Length, LengthTag, Nonce1} = Seal(<<Size:2/unit:8>>, Nonce),
    {Payload, PayloadTag, Nonce2} = Seal(Cur, Nonce1),
    Bcc = [PayloadTag, Payload, LengthTag, Length | Acc],
    encrypt(Seal, Nonce2, Rest, Bcc).           % concat from backword

-spec decrypt(Context, Input) -> {Output, Context}
    when Context :: init() | decrypt_ctx(),
         Input :: binary(),
         Output :: iolist().
decrypt({init, Cipher, MasterKey}, Input) ->
    Info = crypto:cipher_info(Cipher),
    KeySize = map_get(key_length, Info),
    {Salt, Rest} = split_binary(Input, KeySize),
    SubKey = hkdf_sha1(MasterKey, Salt, KeySize),
    Open =
        fun(Data, Tag, Nonce) ->
           Output = crypto:crypto_one_time_aead(Cipher, SubKey, Nonce, Data, <<>>, Tag, false),
           {Output, inc(Nonce)}
        end,
    decrypt(Open, ?ZERO_NONCE, ?HEADER, Rest, []);
decrypt({context, Open, Nonce, Length, Buff}, Input) ->
    decrypt(Open, Nonce, Length, <<Buff/binary, Input/binary>>, []).

% decrypt header
decrypt(Open, Nonce, ?HEADER, Input, Acc) when byte_size(Input) >= 2 + ?TAG_SIZE ->
    <<Data:2/binary, Tag:?TAG_SIZE/binary, Rest/binary>> = Input,
    {<<Length:2/unit:8>>, Nonce1} = Open(Data, Tag, Nonce),
    decrypt(Open, Nonce1, Length, Rest, Acc);
% decrypt payload
decrypt(Open, Nonce, Length, Input, Acc) when byte_size(Input) >= Length + ?TAG_SIZE ->
    <<Data:Length/binary, Tag:?TAG_SIZE/binary, Rest/binary>> = Input,
    {Payload, Nonce1} = Open(Data, Tag, Nonce),
    decrypt(Open, Nonce1, ?HEADER, Rest, [Payload | Acc]);
decrypt(Open, Nonce, Length, Input, Acc) ->
    {lists:reverse(Acc), {context, Open, Nonce, Length, Input}}.

% derive master key from password, use EVP_bytesToKey
-spec derive_key(Pass, Len) -> Key
    when Pass :: string(),
         Len :: non_neg_integer(),
         Key :: binary().
derive_key(Pass, Len) ->
    derive_key(list_to_binary(Pass), <<>>, Len).

derive_key(Pass, Pre, Len) when Len > 16 ->
    Cur = crypto:hash(md5, [Pre, Pass]),
    Rest = derive_key(Pass, Cur, Len - 16),
    <<Cur/binary, Rest/binary>>;
derive_key(Pass, Pre, _) ->
    crypto:hash(md5, [Pre, Pass]).

% derive session key from master key, use HKDF with SHA1
-spec hkdf_sha1(Key, Salt, Len) -> SubKey
    when Key :: binary(),
         Salt :: binary(),
         Len :: non_neg_integer(),
         SubKey :: binary().
hkdf_sha1(Key, Salt, Len) ->
    Prk = crypto:mac(hmac, sha, Salt, Key),
    expand(Prk, <<>>, 1, Len).

expand(Prk, Pre, I, Len) when Len > 20 ->
    Cur = crypto:mac(hmac, sha, Prk, <<Pre/binary, ?INFO, I>>),
    Rest = expand(Prk, Cur, I + 1, Len - 20),
    <<Cur/binary, Rest/binary>>;
expand(Prk, Pre, I, Len) ->
    binary_part(crypto:mac(hmac, sha, Prk, <<Pre/binary, ?INFO, I>>), 0, Len).

inc(I) ->
    add(I, 1).

add(<<I:12/little-unit:8>>, J) ->
    <<(I + J):12/little-unit:8>>.
