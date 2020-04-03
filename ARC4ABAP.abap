FUNCTION zarc4_for_abap.
*"----------------------------------------------------------------------
*"*"Local Interface:
*"  IMPORTING
*"     REFERENCE(XSTREAM) TYPE  XSTRING OPTIONAL
*"     REFERENCE(TSTREAM) TYPE  STRING OPTIONAL
*"     REFERENCE(KEY) TYPE  CHAR256 DEFAULT 'ARC4_KEY'
*"     REFERENCE(MODE) TYPE  CHAR3 DEFAULT 'ASC'
*"  EXPORTING
*"     REFERENCE(OXSTREAM) TYPE  XSTRING
*"  EXCEPTIONS
*"      MULTIPLE_INPUT
*"      NULL_INPUT
*"      DATA_INITIAL
*"      KEY_INITIAL
*"      CONVERSION_FAILED
*"----------------------------------------------------------------------

*======================================================================*
**______________________A R C 4   F O R   A B A P______________________*
**=====================================================================*
** Author            : AJ                                              *
** Created On        : 28.06.2012                                      *
** Objective         : Make a stream cipher ARC4 encryption/decryption *
**                   :   algorithm                                     *
** Version no.       : 1V01    (Change this if required)               *
** Comments	         : Courtsey : WikiPedia                            *
** Liscence          : GPLv2                                           *
**=====================================================================*

  IF xstream IS NOT SUPPLIED
  AND tstream IS NOT SUPPLIED.
    RAISE null_input.
  ENDIF.

  IF STRLEN( key ) EQ 0.
    RAISE key_initial.
  ENDIF.

  IF XSTRLEN( xstream ) EQ 0
  AND STRLEN( tstream ) EQ 0.
    RAISE data_initial.
  ENDIF.

  IF XSTRLEN( xstream ) GT 0
  AND STRLEN( tstream ) GT 0.
    RAISE multiple_input.
  ENDIF.


  FIELD-SYMBOLS : <w_xstrchar> TYPE x.
  DATA  : w_binary    TYPE xstring,
          w_strchar   TYPE c,
          w_xstrchar(2) TYPE x, "For UNICODE
          w_index     TYPE i,   "Temp index
          w_binlen    TYPE i,   "Length of BINARY object
          w_txtlen    TYPE i,   "Length of text stream
          w_xkeylen   TYPE i,   "Length of key

          w_keyxst    TYPE xstring, "Key as binary (ASCII)
          w_keystr    TYPE string,  "Key as string

          w_srand(256) TYPE x,  "Pseudo random string  for ARC4
          w_sswap      TYPE x,  "Swap temp variable
          w_cipherhex  TYPE x,  "Single byte encoded/decoded o/p from stream
          w_inti       TYPE i,  "INT i for ARC4
          w_intj       TYPE i,  "INT j for ARC4
          w_keymod     TYPE i,  "intI MOD keylen
          w_sindex     TYPE i.  "Single byte index for XOR ciphering

  w_binary  = xstream.
  IF XSTRLEN( w_binary ) EQ 0.
    w_txtlen  = STRLEN( tstream ).
    IF mode EQ 'ASC'.
      CALL FUNCTION 'SCMS_STRING_TO_XSTRING'
        EXPORTING
          text   = tstream
        IMPORTING
          buffer = w_binary
        EXCEPTIONS
          failed = 1
          OTHERS = 2.
      IF sy-subrc <> 0.
        RAISE conversion_failed.
      ENDIF.
    ELSE.
      DO w_txtlen TIMES.
        w_index = sy-index - 1.
        w_strchar = tstream+w_index(1).
        ASSIGN w_strchar TO <w_xstrchar> CASTING.
        w_xstrchar  = <w_xstrchar>.
        CONCATENATE w_binary w_xstrchar INTO w_binary IN BYTE MODE.
      ENDDO.
    ENDIF.
  ENDIF.

  w_keystr = key.

  CALL FUNCTION 'SCMS_STRING_TO_XSTRING'
    EXPORTING
      text   = w_keystr
    IMPORTING
      buffer = w_keyxst
    EXCEPTIONS
      failed = 1
      OTHERS = 2.
  IF sy-subrc EQ 0.
    CLEAR : w_keystr.
  ELSE.
    RAISE conversion_failed.
  ENDIF.

  w_xkeylen   = XSTRLEN( w_keyxst ).
  w_binlen    = XSTRLEN( w_binary ).

* THE KEY-SCHEDULING ALGORITHM (KSA)
*    The key-scheduling algorithm is used to initialize the permutation in the array "S".
*    "keylength" is defined as the number of bytes in the key and can be in the range
*    1 = keylength = 256, typically between 5 and 16, corresponding to a key length of 40 – 128 bits.
*    First, the array "S" is initialized to the identity permutation.
*    S is then processed for 256 iterations in a similar way to the main PRGA,
*    but also mixes in bytes of the key at the same time.
*
*      for i from 0 to 255
*          S[i] := i
*      endfor
*      j := 0
*      for i from 0 to 255
*          j := (j + S[i] + key[i mod keylength]) mod 256
*          swap values of S[i] and S[j]
*      endfor
*
*

  WHILE w_inti LT 256.
    w_srand+w_inti(1)  = w_inti.
    w_inti = w_inti + 1.
  ENDWHILE.

  w_inti  = 0.
  w_intj  = 0.

  WHILE w_inti LT 256.
    w_keymod  = w_inti MOD w_xkeylen.
    w_intj  = ( w_intj + w_srand+w_inti(1) + w_keyxst+w_keymod(1) ) MOD 256.

    w_sswap = w_srand+w_inti(1).
    w_srand+w_inti(1) = w_srand+w_intj(1).
    w_srand+w_intj(1) = w_sswap.

    w_inti  = w_inti + 1.
  ENDWHILE.

*THE PSEUDO-RANDOM GENERATION ALGORITHM (PRGA)
*    For as many iterations as are needed, the PRGA modifies the state and outputs a byte of the keystream.
*    In each iteration, the PRGA increments i, looks up the ith element of S, S[i], and adds that to j, exchanges
*    the values of S[i] and S[j], and then uses the sum S[i] + S[j] (modulo 256) as an index to fetch a third
*    element of S, (the keystream value K below) which is XORed with the next byte of the message to produce
*    the next byte of either ciphertext or plaintext. Each element of S is swapped with another element at least
*    once every 256 iterations.
*
*     i := 0
*     j := 0
*     while GeneratingOutput:
*         i := (i + 1) mod 256
*         j := (j + S[i]) mod 256
*         swap values of S[i] and S[j]
*         K := S[(S[i] + S[j]) mod 256]
*         output K
*     endwhile

  w_inti  = 0.
  w_intj  = 0.

  DO w_binlen TIMES.

    w_index = ( sy-index - 1 ). "For xstring problem

    w_inti  = ( w_inti + 1 ) MOD 256.
    w_intj  = ( w_intj + w_srand+w_inti(1) ) MOD 256.

    w_sswap = w_srand+w_inti(1).
    w_srand+w_inti(1) = w_srand+w_intj(1).
    w_srand+w_intj(1) = w_sswap.

    w_sindex = ( w_srand+w_inti(1) + w_srand+w_intj(1) )  MOD 256.

    w_cipherhex = w_srand+w_sindex(1) BIT-XOR w_binary+w_index(1).

    CONCATENATE oxstream w_cipherhex INTO oxstream IN BYTE MODE.
  ENDDO.
ENDFUNCTION.
