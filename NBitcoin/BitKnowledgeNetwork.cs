using System;
using System.Linq;
using NBitcoin.BouncyCastle.Math;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;

namespace NBitcoin
{
	public partial class Network
	{

		public static Network BitKnowledgeMain => InitBitKnowledgeMain();
		public static Network BitKnowledgeTest => InitBitKnowledgeTest();

		private static Network InitBitKnowledgeMain()
		{
			Block.BlockSignature = true;
			Transaction.TimeStamp = true;

			var consensus = new Consensus();

			consensus.SubsidyHalvingInterval = 210000;
			consensus.MajorityEnforceBlockUpgrade = 750;
			consensus.MajorityRejectBlockOutdated = 950;
			consensus.MajorityWindow = 1000;
			consensus.BuriedDeployments[BuriedDeployments.BIP34] = 227931;
			consensus.BuriedDeployments[BuriedDeployments.BIP65] = 388381;
			consensus.BuriedDeployments[BuriedDeployments.BIP66] = 363725;
			consensus.BIP34Hash = new uint256("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
			consensus.PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
			consensus.PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60); // two weeks
			consensus.PowTargetSpacing = TimeSpan.FromSeconds(10 * 60);
			consensus.PowAllowMinDifficultyBlocks = false;
			consensus.PowNoRetargeting = false;
			consensus.RuleChangeActivationThreshold = 1916; // 95% of 2016
			consensus.MinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

			consensus.BIP9Deployments[BIP9Deployments.TestDummy] = new BIP9DeploymentsParameters(28, 1199145601, 1230767999);
			consensus.BIP9Deployments[BIP9Deployments.CSV] = new BIP9DeploymentsParameters(0, 1462060800, 1493596800);
			consensus.BIP9Deployments[BIP9Deployments.Segwit] = new BIP9DeploymentsParameters(1, 0, 0);

			consensus.LastPOWBlock = 12500;

			consensus.ProofOfStakeLimit = new BigInteger(uint256.Parse("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").ToBytes(false));
			consensus.ProofOfStakeLimitV2 = new BigInteger(uint256.Parse("000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffff").ToBytes(false));

			consensus.CoinType = 105;

			var genesis = CreateGenesis(1506729364, 1356975, 0x1e0fffff, 1, Money.Zero);
			consensus.HashGenesisBlock = genesis.GetHash();

			// The message start string is designed to be unlikely to occur in normal data.
			// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
			// a large 4-byte int at any alignment.
			var pchMessageStart = new byte[4];
			pchMessageStart[0] = 0x70;
			pchMessageStart[1] = 0x35;
			pchMessageStart[2] = 0x22;
			pchMessageStart[3] = 0x05;
			var magic = BitConverter.ToUInt32(pchMessageStart, 0); //0x5223570; 

			if (consensus.HashGenesisBlock != uint256.Parse("0x2acd8b136745d0af7c99565acf648cc0dc90bb72bd2652bbf15fb118c5cc0262") ||
				genesis.Header.HashMerkleRoot != uint256.Parse("0x4ef67b97c2eb5ed5a87a2447008912e669b2a6f2a1834487fd5a7fc41532b2a8"))
				throw new InvalidOperationException("Invalid Network");



			var builder = new NetworkBuilder()
				.SetName("BitKnowledgeMain")
				.SetConsensus(consensus)
				.SetMagic(magic)
				.SetGenesis(genesis)
				.SetPort(16179)
				.SetRPCPort(16175)
#if !NOSOCKET
				.AddDNSSeeds(new[] { new DNSSeedData("seed.shuffl.io", "seed.shuffl.io"), new DNSSeedData("seed.bitknowledge.io", "seed.bitknowledge.io") })
#endif
				.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { (63) })
				.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { (125) })
				.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { (63 + 128) })
				.SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_NO_EC, new byte[] { 0x01, 0x42 })
				.SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_EC, new byte[] { 0x01, 0x43 })
				.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { (0x04), (0x88), (0xB2), (0x1E) })
				.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { (0x04), (0x88), (0xAD), (0xE4) })
				.SetBase58Bytes(Base58Type.PASSPHRASE_CODE, new byte[] { 0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2 })
				.SetBase58Bytes(Base58Type.CONFIRMATION_CODE, new byte[] { 0x64, 0x3B, 0xF6, 0xA8, 0x9A })
				.SetBase58Bytes(Base58Type.STEALTH_ADDRESS, new byte[] { 0x2a })
				.SetBase58Bytes(Base58Type.ASSET_ID, new byte[] { 23 })
				.SetBase58Bytes(Base58Type.COLORED_ADDRESS, new byte[] { 0x13 })
				.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, "bc")
				.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, "bc");

#if !NOSOCKET
			// fixed seeds:
			var seeds = new[]
			{
				"198.50.233.74"
			};
			// Convert the pnSeeds array into usable address objects.
			Random rand = new Random();
			TimeSpan nOneWeek = TimeSpan.FromDays(7);
			var vFixedSeeds = seeds.Select(seed => new NetworkAddress
			{
				Time = DateTime.UtcNow - TimeSpan.FromSeconds(rand.NextDouble() * nOneWeek.TotalSeconds) - nOneWeek,
				Endpoint = Utils.ParseIpEndpoint(seed, builder._Port)
			});

			builder.AddSeeds(vFixedSeeds);
#endif
			return builder.BuildAndRegister();
		}

		private static Network InitBitKnowledgeTest()
		{
			Block.BlockSignature = true;
			Transaction.TimeStamp = true;

			var consensus = Main.Consensus.Clone();
			consensus.PowLimit = new Target(uint256.Parse("0000ffff00000000000000000000000000000000000000000000000000000000"));

			// The message start string is designed to be unlikely to occur in normal data.
			// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
			// a large 4-byte int at any alignment.
			var pchMessageStart = new byte[4];
			pchMessageStart[0] = 0x71;
			pchMessageStart[1] = 0x31;
			pchMessageStart[2] = 0x21;
			pchMessageStart[3] = 0x11;
			var magic = BitConverter.ToUInt32(pchMessageStart, 0); //0x5223570; 

			var genesis = Main.GetGenesis().Clone();
			genesis.Header.Time = 1506729300;
			genesis.Header.Nonce = 2162556;
			genesis.Header.Bits = consensus.PowLimit;
			consensus.HashGenesisBlock = genesis.GetHash();

			if (consensus.HashGenesisBlock != uint256.Parse("0xd7851a941b05e4ebf096667f8875866ae58154c400263c04ea4f68e321594a8f"))
				throw new InvalidOperationException("Invalid Network");

			var builder = new NetworkBuilder()
				.SetName("BitKnowledgeTest")
				.SetConsensus(consensus)
				.SetMagic(magic)
				.SetGenesis(genesis)
				.SetPort(26179)
				.SetRPCPort(26175)
				.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { (65) })
				.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { (196) })
				.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { (65 + 128) })
				.SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_NO_EC, new byte[] { 0x01, 0x42 })
				.SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_EC, new byte[] { 0x01, 0x43 })
				.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { (0x04), (0x88), (0xB2), (0x1E) })
				.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { (0x04), (0x88), (0xAD), (0xE4) })

#if !NOSOCKET
				.AddDNSSeeds(new[]
				{
					new DNSSeedData("seed.shuffl.io", "test.shuffl.io"),
				});
#endif

			return builder.BuildAndRegister();
		}

		private static Block CreateGenesis(uint nTime, uint nNonce, uint nBits, int nVersion, Money genesisReward)
		{
			string pszTimestamp = "https://twitter.com/SpaceX/status/913632410549366784";
			Transaction txNew = new Transaction();
			txNew.Version = 1;
			txNew.Time = nTime;

			Op op = Op.GetPushOp(new byte[0]);
			op.Code = (OpcodeType)0x1;
			op.PushData = new[] { (byte)42 };

			txNew.AddInput(new TxIn
			{
				ScriptSig = new Script(Op.GetPushOp(0), new Op
				{
					Code = (OpcodeType)0x1,
					PushData = new[] { (byte)42 }
				}, Op.GetPushOp(Encoders.ASCII.DecodeData(pszTimestamp)))
			});
			txNew.AddOutput(new TxOut()
			{
				Value = genesisReward,
			});
			Block genesis = new Block();
			genesis.Header.BlockTime = Utils.UnixTimeToDateTime(nTime);
			genesis.Header.Bits = nBits;
			genesis.Header.Nonce = nNonce;
			genesis.Header.Version = nVersion;
			genesis.Transactions.Add(txNew);
			genesis.Header.HashPrevBlock = uint256.Zero;
			genesis.UpdateMerkleRoot();
			return genesis;
		}
	}
}
