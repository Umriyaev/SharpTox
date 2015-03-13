﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using SharpTox.Core;

namespace SharpTox.Test
{
    [TestClass]
    public class MiscTests
    {
        private ToxOptions _options = new ToxOptions(true, true);

        [TestMethod]
        public void TestToxBootstrapAndConnect()
        {
            var tox = new Tox(_options);
            var error = ToxErrorBootstrap.Ok;

            foreach (var node in Globals.Nodes)
            {
                bool result = tox.Bootstrap(node, out error);
                if (!result || error != ToxErrorBootstrap.Ok)
                    Assert.Fail("Failed to bootstrap error: {0}, result: {1}", error, result);
            }

            tox.Start();
            while (!tox.IsConnected) { }

            Console.WriteLine("Tox connected!");
            tox.Dispose();
        }

        [TestMethod]
        public void TestToxBootstrapAndConnectTcp()
        {
            var tox = new Tox(new ToxOptions(true, false));
            var error = ToxErrorBootstrap.Ok;

            bool result = tox.AddTcpRelay(new ToxNode("104.219.184.206", 443, new ToxKey(ToxKeyType.Public, "8CD087E31C67568103E8C2A28653337E90E6B8EDA0D765D57C6B5172B4F1F04C")), out error);
            if (!result || error != ToxErrorBootstrap.Ok)
                Assert.Fail("Failed to bootstrap error: {0}, result: {1}", error, result);

            tox.Start();
            while (!tox.IsConnected) { }

            Console.WriteLine("Tox connected!");
            tox.Dispose();
        }
    }
}