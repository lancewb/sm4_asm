#include "textflag.h"
#define TMP0    X8
#define TMP1    X9
#define TMP2    X10
#define TMP3    X11
#define TMP4    X12
#define RX0     X13
#define RX1     X14
#define BITMASK X15

#define transpose_4x4(x0, x1, x2, x3, t1, t2) \
        VPUNPCKHDQ x1, x0, t2;\
        VPUNPCKLDQ x1, x0, x0;\
        VPUNPCKLDQ x3, x2, t1;\
        VPUNPCKHDQ x3, x2, x2;\
        VPUNPCKHQDQ t1, x0, x1;\
        VPUNPCKLQDQ t1, x0, x0;\
        VPUNPCKHQDQ x2, t2, x3;\
        VPUNPCKLQDQ x2, t2, x2

#define transform_pre(x, lo_t, hi_t, mask4bit, tmp0)\
        VPAND x, mask4bit, tmp0;\
        VPANDN x, mask4bit, x;\
        VPSRLD $4, x, x;\
        VPSHUFB tmp0, lo_t, tmp0;\
        VPSHUFB x, hi_t, x;\
        VPXOR tmp0, x, x

#define transform_post(x, lo_t, hi_t, mask4bit, tmp0)\
        VPANDN mask4bit, x, tmp0;\
        VPSRLD $4, x, x;\
        VPAND x, mask4bit, x;\
        VPSHUFB tmp0, lo_t, tmp0;\
        VPSHUFB x, hi_t, x;\
        VPXOR tmp0, x, x

// pre-SubByte affine transform, from SM4 field to AES field.
DATA ·PRE_TF_LO_S<>+0(SB)/8,    $0X9197E2E474720701
DATA ·PRE_TF_LO_S<>+8(SB)/8,    $0XC7C1B4B222245157
GLOBL ·PRE_TF_LO_S<>(SB), (NOPTR+RODATA), $16

DATA ·PRE_TF_HI_S<>+0(SB)/8,    $0XE240AB09EB49A200
DATA ·PRE_TF_HI_S<>+8(SB)/8,    $0XF052B91BF95BB012
GLOBL ·PRE_TF_HI_S<>(SB), (NOPTR+RODATA), $16

// post-SubByte affine transform, from AES field to SM4 field.
DATA ·POST_TF_LO_S<>+0(SB)/8,    $0X5B67F2CEA19D0834
DATA ·POST_TF_LO_S<>+8(SB)/8,    $0XEDD14478172BBE82
GLOBL ·POST_TF_LO_S<>(SB), (NOPTR+RODATA), $16

DATA ·POST_TF_HI_S<>+0(SB)/8,    $0XAE7201DD73AFDC00
DATA ·POST_TF_HI_S<>+8(SB)/8,    $0X11CDBE62CC1063BF
GLOBL ·POST_TF_HI_S<>(SB), (NOPTR+RODATA), $16

// For isolating SubBytes from AESENCLAST, inverse shift row
DATA ·INV_SHIFT_ROW<>+0(SB)/1,    $0X00
DATA ·INV_SHIFT_ROW<>+1(SB)/1,    $0X0D
DATA ·INV_SHIFT_ROW<>+2(SB)/1,    $0X0A
DATA ·INV_SHIFT_ROW<>+3(SB)/1,    $0X07
DATA ·INV_SHIFT_ROW<>+4(SB)/1,    $0X04
DATA ·INV_SHIFT_ROW<>+5(SB)/1,    $0X01
DATA ·INV_SHIFT_ROW<>+6(SB)/1,    $0X0E
DATA ·INV_SHIFT_ROW<>+7(SB)/1,    $0X0B
DATA ·INV_SHIFT_ROW<>+8(SB)/1,    $0X08
DATA ·INV_SHIFT_ROW<>+9(SB)/1,    $0X05
DATA ·INV_SHIFT_ROW<>+10(SB)/1,    $0X02
DATA ·INV_SHIFT_ROW<>+11(SB)/1,    $0X0F
DATA ·INV_SHIFT_ROW<>+12(SB)/1,    $0X0C
DATA ·INV_SHIFT_ROW<>+13(SB)/1,    $0X09
DATA ·INV_SHIFT_ROW<>+14(SB)/1,    $0X06
DATA ·INV_SHIFT_ROW<>+15(SB)/1,    $0X03
GLOBL ·INV_SHIFT_ROW<>(SB), (NOPTR+RODATA), $16

// Inverse shift row + Rotate left by 8 bits on 32-bit words with vpshufb
DATA ·INV_SHIFT_ROW_ROL_8<>+0(SB)/1,    $0X07
DATA ·INV_SHIFT_ROW_ROL_8<>+1(SB)/1,    $0X00
DATA ·INV_SHIFT_ROW_ROL_8<>+2(SB)/1,    $0X0D
DATA ·INV_SHIFT_ROW_ROL_8<>+3(SB)/1,    $0X0A
DATA ·INV_SHIFT_ROW_ROL_8<>+4(SB)/1,    $0X0B
DATA ·INV_SHIFT_ROW_ROL_8<>+5(SB)/1,    $0X04
DATA ·INV_SHIFT_ROW_ROL_8<>+6(SB)/1,    $0X01
DATA ·INV_SHIFT_ROW_ROL_8<>+7(SB)/1,    $0X0E
DATA ·INV_SHIFT_ROW_ROL_8<>+8(SB)/1,    $0X0F
DATA ·INV_SHIFT_ROW_ROL_8<>+9(SB)/1,    $0X08
DATA ·INV_SHIFT_ROW_ROL_8<>+10(SB)/1,    $0X05
DATA ·INV_SHIFT_ROW_ROL_8<>+11(SB)/1,    $0X02
DATA ·INV_SHIFT_ROW_ROL_8<>+12(SB)/1,    $0X03
DATA ·INV_SHIFT_ROW_ROL_8<>+13(SB)/1,    $0X0C
DATA ·INV_SHIFT_ROW_ROL_8<>+14(SB)/1,    $0X09
DATA ·INV_SHIFT_ROW_ROL_8<>+15(SB)/1,    $0X06
GLOBL ·INV_SHIFT_ROW_ROL_8<>(SB), (NOPTR+RODATA), $16

// Inverse shift row + Rotate left by 16 bits on 32-bit words with vpshufb
DATA ·INV_SHIFT_ROW_ROL_16<>+0(SB)/1,    $0X0A
DATA ·INV_SHIFT_ROW_ROL_16<>+1(SB)/1,    $0X07
DATA ·INV_SHIFT_ROW_ROL_16<>+2(SB)/1,    $0X00
DATA ·INV_SHIFT_ROW_ROL_16<>+3(SB)/1,    $0X0D
DATA ·INV_SHIFT_ROW_ROL_16<>+4(SB)/1,    $0X0E
DATA ·INV_SHIFT_ROW_ROL_16<>+5(SB)/1,    $0X0B
DATA ·INV_SHIFT_ROW_ROL_16<>+6(SB)/1,    $0X04
DATA ·INV_SHIFT_ROW_ROL_16<>+7(SB)/1,    $0X01
DATA ·INV_SHIFT_ROW_ROL_16<>+8(SB)/1,    $0X02
DATA ·INV_SHIFT_ROW_ROL_16<>+9(SB)/1,    $0X0F
DATA ·INV_SHIFT_ROW_ROL_16<>+10(SB)/1,    $0X08
DATA ·INV_SHIFT_ROW_ROL_16<>+11(SB)/1,    $0X05
DATA ·INV_SHIFT_ROW_ROL_16<>+12(SB)/1,    $0X06
DATA ·INV_SHIFT_ROW_ROL_16<>+13(SB)/1,    $0X03
DATA ·INV_SHIFT_ROW_ROL_16<>+14(SB)/1,    $0X0C
DATA ·INV_SHIFT_ROW_ROL_16<>+15(SB)/1,    $0X09
GLOBL ·INV_SHIFT_ROW_ROL_16<>(SB), (NOPTR+RODATA), $16

// Inverse shift row + Rotate left by 24 bits on 32-bit words with vpshufb
DATA ·INV_SHIFT_ROW_ROL_24<>+0(SB)/1,    $0X0D
DATA ·INV_SHIFT_ROW_ROL_24<>+1(SB)/1,    $0X0A
DATA ·INV_SHIFT_ROW_ROL_24<>+2(SB)/1,    $0X07
DATA ·INV_SHIFT_ROW_ROL_24<>+3(SB)/1,    $0X00
DATA ·INV_SHIFT_ROW_ROL_24<>+4(SB)/1,    $0X01
DATA ·INV_SHIFT_ROW_ROL_24<>+5(SB)/1,    $0X0E
DATA ·INV_SHIFT_ROW_ROL_24<>+6(SB)/1,    $0X0B
DATA ·INV_SHIFT_ROW_ROL_24<>+7(SB)/1,    $0X04
DATA ·INV_SHIFT_ROW_ROL_24<>+8(SB)/1,    $0X05
DATA ·INV_SHIFT_ROW_ROL_24<>+9(SB)/1,    $0X02
DATA ·INV_SHIFT_ROW_ROL_24<>+10(SB)/1,    $0X0F
DATA ·INV_SHIFT_ROW_ROL_24<>+11(SB)/1,    $0X08
DATA ·INV_SHIFT_ROW_ROL_24<>+12(SB)/1,    $0X09
DATA ·INV_SHIFT_ROW_ROL_24<>+13(SB)/1,    $0X06
DATA ·INV_SHIFT_ROW_ROL_24<>+14(SB)/1,    $0X03
DATA ·INV_SHIFT_ROW_ROL_24<>+15(SB)/1,    $0X0C
GLOBL ·INV_SHIFT_ROW_ROL_24<>(SB), (NOPTR+RODATA), $16

// For CTR-mode IV byteswap
DATA ·BSWAP128_MASK<>+0(SB)/1,    $15
DATA ·BSWAP128_MASK<>+1(SB)/1,    $14
DATA ·BSWAP128_MASK<>+2(SB)/1,    $13
DATA ·BSWAP128_MASK<>+3(SB)/1,    $12
DATA ·BSWAP128_MASK<>+4(SB)/1,    $11
DATA ·BSWAP128_MASK<>+5(SB)/1,    $10
DATA ·BSWAP128_MASK<>+6(SB)/1,    $9
DATA ·BSWAP128_MASK<>+7(SB)/1,    $8
DATA ·BSWAP128_MASK<>+8(SB)/1,    $7
DATA ·BSWAP128_MASK<>+9(SB)/1,    $6
DATA ·BSWAP128_MASK<>+10(SB)/1,    $5
DATA ·BSWAP128_MASK<>+11(SB)/1,    $4
DATA ·BSWAP128_MASK<>+12(SB)/1,    $3
DATA ·BSWAP128_MASK<>+13(SB)/1,    $2
DATA ·BSWAP128_MASK<>+14(SB)/1,    $1
DATA ·BSWAP128_MASK<>+15(SB)/1,    $0
GLOBL ·BSWAP128_MASK<>(SB), (NOPTR+RODATA), $16

// For input word byte-swap
DATA ·BSWAP32_MASK<>+0(SB)/1,    $3
DATA ·BSWAP32_MASK<>+1(SB)/1,    $2
DATA ·BSWAP32_MASK<>+2(SB)/1,    $1
DATA ·BSWAP32_MASK<>+3(SB)/1,    $0
DATA ·BSWAP32_MASK<>+4(SB)/1,    $7
DATA ·BSWAP32_MASK<>+5(SB)/1,    $6
DATA ·BSWAP32_MASK<>+6(SB)/1,    $5
DATA ·BSWAP32_MASK<>+7(SB)/1,    $4
DATA ·BSWAP32_MASK<>+8(SB)/1,    $11
DATA ·BSWAP32_MASK<>+9(SB)/1,    $10
DATA ·BSWAP32_MASK<>+10(SB)/1,    $9
DATA ·BSWAP32_MASK<>+11(SB)/1,    $8
DATA ·BSWAP32_MASK<>+12(SB)/1,    $15
DATA ·BSWAP32_MASK<>+13(SB)/1,    $14
DATA ·BSWAP32_MASK<>+14(SB)/1,    $13
DATA ·BSWAP32_MASK<>+15(SB)/1,    $12
GLOBL ·BSWAP32_MASK<>(SB), (NOPTR+RODATA), $16

// 4-bit mask
DATA ·BIT_MASK4<>+0(SB)/4,    $0x0f0f0f0f
GLOBL ·BIT_MASK4<>(SB), (NOPTR+RODATA), $4

// 12 bytes, only for padding
DATA ·PADDING_DEADBEEF<>+0(SB)/4,    $0xdeadbeef
DATA ·PADDING_DEADBEEF<>+4(SB)/4,    $0xdeadbeef
DATA ·PADDING_DEADBEEF<>+8(SB)/4,    $0xdeadbeef
GLOBL ·PADDING_DEADBEEF<>(SB), (NOPTR+RODATA), $12

// Sm4AvxCrypt4(rk(32*4bytes),src(64bytes),dst(64bytes),blockNum(8bytes))
TEXT Sm4AvxCrypt4(SB),NOSPLIT,$0
    MOVQ    src+8(FP),    BX
	VMOVDQA    (BX),         X1
    VMOVDQA    X0,           X1
    VMOVDQA    X0,           X2
    VMOVDQA    X0,           X3
    MOVQ        $2,         AX
    CMPQ        AX,           blockNum+24(FP)
    JCS         blk4_loadInputFin
    VMOVDQU     16(BX),    X1
    JE          blk4_loadInputFin
    VMOVDQU     32(BX),    X2
    MOVQ        $3,         AX
    CMPQ        AX,           blockNum+24(FP)
    JE        	blk4_loadInputFin
    VMOVDQU    	48(BX),    X3

blk4_loadInputFin:
    VMOVDQA    ·bswap32_mask<>(SB),    TMP2
    VPSHUFB    TMP2,    X0,    X0
    VPSHUFB    TMP2,    X1,    X1
    VPSHUFB    TMP2,    X2,    X2
    VPSHUFB    TMP2,    X3,    X3
    VBROADCASTSS    ·bit_mask4<>(SB),    		BITMASK    
    VMOVDQA         ·pre_tf_lo_s<>(SB),       	TMP4
    VMOVDQA         ·pre_tf_hi_s<>(SB),       	X4
    VMOVDQA         ·post_tf_lo_s<>(SB),      	X5
    VMOVDQA         ·post_tf_hi_s<>(SB),      	X6
    VMOVDQA         ·inv_shift_row<>(SB),     	X7
    VMOVDQA         ·inv_shift_row_rol_8<>(SB), TMP2
    VMOVDQA         ·inv_shift_row_rol_16<>(SB),TMP3
    transpose_4x4(X0,X1,X2,X3,TMP0,TMP1)

#define ROUND(round, s0, s1, s2, s3)\
        VBROADCASTSS (4*round)(BX), RX0;\
        VPXOR s1, RX0, RX0;\
        VPXOR s2, RX0, RX0;\
        VPXOR s3, RX0, RX0;\
        transform_pre(RX0, TMP4, X4, BITMASK, TMP0);\
        VAESENCLAST BITMASK, RX0, RX0;\
        transform_post(RX0, X5, X6, BITMASK, TMP0);\
        VPSHUFB X7, RX0, TMP0;\
        VPXOR TMP0, s0, s0;\
        VPSHUFB TMP2, RX0, TMP1;\
        VPXOR TMP1, TMP0, TMP0;\
        VPSHUFB TMP3, RX0, TMP1;\
        VPXOR TMP1, TMP0, TMP0;\
        VPSHUFB ·inv_shift_row_rol_24<>(SB), RX0, TMP1;\
        VPXOR TMP1, s0, s0;\
        VPSLLD $2, TMP0, TMP1;\
        VPSRLD $30, TMP0, TMP0;\
        VPXOR TMP0, s0, s0;\
        VPXOR TMP1, s0, s0
        
    MOVQ    rk+0(FP),	BX
	LEAQ	(32*4)(BX),	CX
roundloop_blk4:
    ROUND(0, X0, X1, X2, X3)
    ROUND(1, X1, X2, X3, X0)
    ROUND(2, X2, X3, X0, X1)
    ROUND(3, X3, X0, X1, X2)
    LEAQ	(4*4)(BX),	BX
	CMPQ	CX,			BX
	JNE		roundloop_blk4
#undef ROUND
	VMOVDQA ·bswap128_mask<>(SB), TMP2

	transpose_4x4(X0, X1, X2, X3, TMP0, TMP1)
	VPSHUFB TMP2, X0, X0
	VPSHUFB TMP2, X1, X1
	VPSHUFB TMP2, X2, X2
	VPSHUFB TMP2, X3, X3

	MOVQ	dst+16(FP),	DX
	VMOVDQU X0, 0*16(DX)
	MOVQ	$2,	AX
	CMPQ 	AX, blockNum+24(FP)
	JCS blk4_storeOutputFin
	VMOVDQU X1, 1*16(DX)
	JE blk4_storeOutputFin
	VMOVDQU X2, 2*16(DX)
	MOVQ	$3,	AX
	CMPQ 	AX, blockNum+24(FP)
	JE blk4_storeOutputFin
	VMOVDQU X3, 3*16(DX)

blk4_storeOutputFin:
	VZEROALL
	RET

TEXT __sm4_crypt_blk8(SB),NOSPLIT,$0
    VMOVDQA    ·bswap32_mask<>(SB),    TMP2
    VPSHUFB    TMP2,    X0,    X0
    VPSHUFB    TMP2,    X1,    X1
    VPSHUFB    TMP2,    X2,    X2
    VPSHUFB    TMP2,    X3,    X3
    VPSHUFB    TMP2,    X4,    X4
    VPSHUFB    TMP2,    X5,    X5
    VPSHUFB    TMP2,    X6,    X6
    VPSHUFB    TMP2,    X7,    X7

    VBROADCASTSS    ·bit_mask4<>(SB),    		BITMASK
    transpose_4x4(X0, X1, X2, X3, TMP0, TMP1)
    transpose_4x4(X4, X5, X6, X7, TMP0, TMP1)

#define ROUND(round, s0, s1, s2, s3, r0, r1, r2, r3)\
        MOVQ    rk+0(FP),    BX;\
        VBROADCASTSS (4*round)(BX), RX0;\
        VMOVDQA ·pre_tf_lo_s<>(SB), TMP4;\
        VMOVDQA ·pre_tf_hi_s<>(SB), TMP1;\
        VMOVDQA X0, X1;\
        VPXOR   s1, X0, X0;\
        VPXOR   s2, X0, X0;\
        VPXOR   s3, X0, X0;\
        VMOVDQA ·post_tf_lo_s<>(SB), TMP2;\
        VMOVDQA ·post_tf_hi_s<>(SB), TMP3;\
        VPXOR   r1, X1, X1;\
        VPXOR   r2, X1, X1;\
        VPXOR   r3, X1, X1;\
        transform_pre(RX0, TMP4, TMP1, BITMASK, TMP0);\
        transform_pre(RX1, TMP4, TMP1, BITMASK, TMP0);\
        VMOVDQA ·inv_shift_row<>(SB),   TMP4;\
        VAESENCLAST BITMASK, RX0, RX0;\
        VAESENCLAST BITMASK, RX1, RX1;\
        transform_post(RX0, TMP2, TMP3, BITMASK, TMP0);\
        transform_post(RX1, TMP2, TMP3, BITMASK, TMP0);\
        VPSHUFB TMP4, RX0, TMP0;\
        VPXOR TMP0, s0, s0;\
        VPSHUFB TMP4, RX1, TMP2;\
        VMOVDQA ·inv_shift_row_rol_8<>(SB), TMP4;\
        VPXOR TMP2, r0, r0;\
        VPSHUFB TMP4, RX0, TMP1;\
        VPXOR TMP1, TMP0, TMP0;\
        VPSHUFB TMP4, RX1, TMP3;\
        VMOVDQA ·inv_shift_row_rol_16<>(SB), TMP4;\
        VPXOR TMP3, TMP2, TMP2;\
        VPSHUFB TMP4, RX0, TMP1;\
        VPXOR TMP1, TMP0, TMP0;\
        VPSHUFB TMP4, RX1, TMP3;\
        VMOVDQA ·inv_shift_row_rol_24<>(SB), TMP4;\
        VPXOR TMP3, TMP2, TMP2;\
        VPSHUFB TMP4, RX0, TMP1;\
        VPXOR TMP1, s0, s0;\
        VPSLLD $2, TMP0, TMP1;\
        VPSRLD $30, TMP0, TMP0;\
        VPXOR TMP0, s0, s0;\
        VPXOR TMP1, s0, s0;\
        VPSHUFB TMP4, RX1, TMP3;\
        VPXOR TMP3, r0, r0;\
        VPSLLD $2, TMP2, TMP3;\
        VPSRLD $30, TMP2, TMP2;\
        VPXOR TMP2, r0, r0;\
        VPXOR TMP3, r0, r0
        
    MOVQ    rk+0(FP),	BX
	LEAQ	(32*4)(BX),	CX

roundloop_blk8:
    ROUND(0, X0, X1, X2, X3, X4, X5, X6, X7)
    ROUND(1, X1, X2, X3, X0, X5, X6, X7, X4)
    ROUND(2, X2, X3, X0, X1, X6, X7, X4, X5)
    ROUND(3, X3, X0, X1, X2, X7, X4, X5, X6)
    MOVQ    rk+0(FP),	BX
    LEAQ	(4*4)(BX),	BX
	CMPQ	CX,			BX
	JNE		roundloop_blk8

#undef ROUND
	VMOVDQA ·bswap128_mask<>(SB), TMP2

	transpose_4x4(X0, X1, X2, X3, TMP0, TMP1)
    transpose_4x4(X4, X5, X6, X7, TMP0, TMP1)
	VPSHUFB TMP2, X0, X0
	VPSHUFB TMP2, X1, X1
	VPSHUFB TMP2, X2, X2
	VPSHUFB TMP2, X3, X3
	VPSHUFB TMP2, X4, X4
	VPSHUFB TMP2, X5, X5
	VPSHUFB TMP2, X6, X6
	VPSHUFB TMP2, X7, X7
    RET




//Sm4AvxCrypt8(rk(32*4bytes),src(64bytes),dst(64bytes),blockNum(8bytes))
TEXT Sm4AvxCrypt8(SB),NOSPLIT,$0
    MOVQ        $5,             AX
    CMPQ        AX,             blockNum+24(FP)
    CALL        ·Sm4AvxCrypt4<>(SB)

    MOVQ        src+8(FP),      BX
    VMOVDQU     (BX),           X0
    VMOVDQU     1*16(BX),       X1
    VMOVDQU     2*16(BX),       X2
    VMOVDQU     3*16(BX),       X3
    VMOVDQU     4*16(BX),       X4
    VMOVDQA     X4,             X5
    VMOVDQA     X4,             X6
    VMOVDQA     X4,             X7
    JE          blk8_loadInputFin
    VMOVDQU     5*16(BX),       X5
    MOVQ        $7,             AX
    CMPQ        AX,           blockNum+24(FP)
    JCS         blk8_loadInputFin
    VMOVDQU     6*16(BX),       X6
    JE          blk8_loadInputFin
    VMOVDQU     7*16(BX),       X7

blk8_loadInputFin:
/** TODO: --------------------------------*/
    CALL ·__sm4_crypt_blk8<>(SB)
    MOVQ        $6,             AX
	CMPQ AX, blockNum+24(FP)
    MOVQ dst+16(FP), DX
	VMOVDQU X0, (0 * 16)(DX)
	VMOVDQU X1, (1 * 16)(DX)
	VMOVDQU X2, (2 * 16)(DX)
	VMOVDQU X3, (3 * 16)(DX)
	VMOVDQU X4, (4 * 16)(DX)
	JCS blk8_store_output_done
	VMOVDQU X5, (5 * 16)(DX)
	JE blk8_store_output_done
	VMOVDQU X6, (6 * 16)(DX)
    MOVQ        $7,             AX
	CMPQ AX, blockNum+24(FP)
	JE blk8_store_output_done
	VMOVDQU X7, (7 * 16)(DX)

blk8_store_output_done:
	VZEROALL
	RET


