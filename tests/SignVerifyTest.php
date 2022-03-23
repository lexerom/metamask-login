<?php

namespace lexerom;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class SignVerifyTest extends TestCase
{
    /**
     * @test
     */
    public function valid(): void
    {
        $signVerify = new SignVerify();
        self::assertTrue($signVerify->verify(
            'must sign:123',
            '0x6171238faa84cb9b938900acce9ff487a8757da9a906ef89c800c2d38c6240d320b1abe3b087afac8be6ed09db2c8bf19ae9388fbcda8b35f93e766a8abd5f691b',
            '0x95F64eCd5426e439c177846ac8Aadb1AC7aAE027',
        ));
    }

    /**
     * @test
     */
    public function invalid(): void
    {
        $signVerify = new SignVerify();
        self::assertFalse($signVerify->verify(
            'must sign:123 sign verify',
            '0x6171238faa84cb9b938900acce9ff487a8757da9a906ef89c800c2d38c6240d320b1abe3b087afac8be6ed09db2c8bf19ae9388fbcda8b35f93e766a8abd5f691b',
            '0x95F64eCd5426e439c177846ac8Aadb1AC7aAE027',
        ));
    }

    /**
     * @test
     */
    public function invalidLength(): void
    {
        $signVerify = new SignVerify();
        self::expectException(InvalidArgumentException::class);
        self::expectExceptionMessage('Invalid signature length');
        $signVerify->verify(
            'must sign:123',
            '0x6171238faa84cb9b938900acce9ff487a8757da9a906ef89c800c2d38c6240d320b1abe3b087afac8be6ed09db2c8bf19ae9388fbcda8b35f93e766a8abd5f',
            '0x95F64eCd5426e439c177846ac8Aadb1AC7aAE027',
        );
    }

    /**
     * @test
     */
    public function invalidSignature(): void
    {
        $signVerify = new SignVerify();
        self::expectException(InvalidArgumentException::class);
        self::expectExceptionMessage('Invalid signature');
        $signVerify->verify(
            'must sign:123',
            '0x7171238faa84cb9b938900acce9ff487a8757da9a906ef89c800c2d38c6240d320b1abe3b087afac8be6ed09db2c8bf19ae9388fbcda8b35f93e766a8abd5f',
            '0x95F64eCd5426e439c177846ac8Aadb1AC7aAE027',
        );
    }
}