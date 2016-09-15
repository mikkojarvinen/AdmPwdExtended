using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using AdmPwd.Utils;
using AdmPwd.PSTypes;

namespace AdmPwd.UI
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private string computerDN=null;

        private void btnSearch_Click(object sender, EventArgs e)
        {
            if (txtComputerName.Text.Trim() == string.Empty)
            {
                lblStatus.Text = "You must enter a computer name";
                return;
            }
            lblStatus.Text = string.Empty;
            string computerDN;

            if (txtComputerName.Text.StartsWith("CN=", StringComparison.InvariantCultureIgnoreCase))
            {
                computerDN = txtComputerName.Text;
            }
            else
            {
                List<string>DNs=DirectoryUtils.GetComputerDN(txtComputerName.Text);
                if(DNs.Count==0) {
                    lblStatus.Text="Computer not found";
                    return;
                }
                if(DNs.Count>1) {
                    lblStatus.Text="Computer name ambiguous, use DN instead of computer name";
                    return;
                }
                computerDN = DNs[0];
            }
            PasswordInfo pi = DirectoryUtils.GetPasswordInfo(computerDN);
            if (pi == null)
            {
                lblStatus.Text = "Computer not found";
                return;
            }
            this.txtPassword.Text = pi.Password;
            this.txtCurrentPwdExpiration.Text = pi.ExpirationTimestamp.ToString();
            this.computerDN = pi.DistinguishedName;
        }

        private void btnExit_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void btnForceExpiration_Click(object sender, EventArgs e)
        {
            lblStatus.Text = string.Empty;
            if (this.computerDN == null)
            {
                lblStatus.Text="No computer selected";
                    return;
            }
            DateTime newPwdExpiration = DateTime.Now;
            if (txtPwdExpiration.Text.Trim() != string.Empty)
            {
                try
                {
                    newPwdExpiration = System.Convert.ToDateTime(txtPwdExpiration.Text.Trim());
                }
                catch (FormatException)
                {
                    lblStatus.Text="Invalid format of date/time";
                    return;
                }
            }
            try {
                DirectoryUtils.ResetPassword(this.computerDN,newPwdExpiration);
                //this.txtPwdExpiration.Text = null;
                //read back from AD
                PasswordInfo pi = DirectoryUtils.GetPasswordInfo(computerDN);
                if (pi == null)
                {
                    lblStatus.Text = "Computer not found";
                    return;
                }
                this.txtPassword.Text = pi.Password;
                this.txtCurrentPwdExpiration.Text = pi.ExpirationTimestamp.ToString();
                this.computerDN = pi.DistinguishedName;
            }
            catch(Exception) {
                lblStatus.Text="Failed to request password reset";
                return;
            }
            lblStatus.Text = "Password reset request was successful";
        }
    }
}
