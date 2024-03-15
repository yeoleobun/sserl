-module(cipher).
-export([hkdf_sha1/3, derive_key/2]).
-define(INFO, "ss-subkey").
-spec derive_key(Pass :: binary(), Len :: integer()) -> iodata().
-spec hkdf_sha1(Key :: binary(), Salt :: binary(), L :: integer()) -> iodata().
derive_key(Pass, Len) ->
    derive_key(Pass, <<>>, [], Len div 16).

derive_key(_, _, Acc, 0) ->
    lists:reverse(Acc);
derive_key(Pass, Pre, Acc, N) ->
    Cur = crypto:hash(md5, [Pre, Pass]),
    derive_key(Pass, Cur, [Cur | Acc], N - 1).

hkdf_sha1(Key, Salt, L) ->
    Prk = crypto:mac(hmac, sha, Salt, Key), % extract
    expand(Prk, <<>>, [], 0, L).

expand(Prk, Pre, Acc, I, L) when I * 20 < L ->
    Mac = crypto:mac(hmac, sha, Prk, <<Pre/binary, ?INFO, (I + 1)>>),
    Cur = binary:part(Mac, 0, min(20, L - I * 20)),
    expand(Prk, Cur, [Cur | Acc], I + 1, L);
expand(_, _, Acc, _, _) ->
    lists:reverse(Acc).
