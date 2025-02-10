#
# Copyright 2024 Centreon (http://www.centreon.com/)
#
# Centreon is a full-fledged industry-strength solution that meets
# the needs in IT infrastructure and application monitoring for
# service performance.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors : Galeax (Amine Hazi)
#

package apps::cyberwatch::restapi::mode::globalstats;

use base qw(centreon::plugins::mode);
use strict;
use warnings;

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(%options);
    $self->{version} = '1.0';

    # Declare CLI options
    $options{options}->add_options(arguments => {
        'hostname:s'     => { name => 'hostname' },
        'port:s'         => { name => 'port', default => 443 },
        'api-username:s' => { name => 'api_username' },
        'api-password:s' => { name => 'api_password' },

        # Thresholds for total CVEs
        'warning-cves:s'    => { name => 'warning_cves' },
        'critical-cves:s'   => { name => 'critical_cves' },

        # Thresholds for assets needing reboot
        'warning-assets-need-reboot:s'  => { name => 'warning_assets_need_reboot' },
        'critical-assets-need-reboot:s' => { name => 'critical_assets_need_reboot' },

        # Thresholds for obsolete OS
        'warning-assets-obsolete:s'  => { name => 'warning_assets_obsolete' },
        'critical-assets-obsolete:s' => { name => 'critical_assets_obsolete' },
    });
    
    bless $self, $class;
    return $self;
}

sub check_options {
    my ($self, %options) = @_;
    $self->SUPER::init(%options);

    # Ensure required options
    foreach my $param (qw(hostname api_username api_password)) {
        if (!defined($self->{option_results}->{$param}) || $self->{option_results}->{$param} eq '') {
            $self->{output}->add_option_msg(short_msg => "Need to specify --$param.");
            $self->{output}->option_exit();
        }
    }

    # Register thresholds in the perfdata engine
    # CVEs
    $self->{perfdata}->threshold_validate(label => 'warning-cves',  value => $self->{option_results}->{warning_cves});
    $self->{perfdata}->threshold_validate(label => 'critical-cves', value => $self->{option_results}->{critical_cves});

    # Assets need reboot
    $self->{perfdata}->threshold_validate(label => 'warning-assets-need-reboot',  value => $self->{option_results}->{warning_assets_need_reboot});
    $self->{perfdata}->threshold_validate(label => 'critical-assets-need-reboot', value => $self->{option_results}->{critical_assets_need_reboot});

    # Obsolete OS
    $self->{perfdata}->threshold_validate(label => 'warning-assets-obsolete',  value => $self->{option_results}->{warning_assets_obsolete});
    $self->{perfdata}->threshold_validate(label => 'critical-assets-obsolete', value => $self->{option_results}->{critical_assets_obsolete});
}

sub run {
    my ($self, %options) = @_;

    # Retrieve the custom API object
    my $custom_api = $options{custom};
    $custom_api->set_options(option_results => $self->{option_results});

    # Fetch all assets
    my $assets = $custom_api->get_assets();
    my $total_assets = scalar(@$assets);

    # Prepare counters
    my $assets_no_cve               = 0;
    my $assets_no_prioritized_cve   = 0; 
    my $assets_with_cve             = 0;
    my $assets_with_prioritized_cve = 0;
    my $assets_obsolete             = 0;
    my $assets_pending_reboot       = 0;
    my $assets_lost_communication   = 0;
    my $total_cves                  = 0;

    # Loop and compute metrics
    foreach my $asset (@$assets) {
        my $asset_id = $asset->{id};
        my $info     = $custom_api->get_asset_security_info(asset_id => $asset_id);

        # cve_announcements_count (total CVEs)
        my $cve_count     = (defined $info->{cve_announcements_count}) 
                            ? $info->{cve_announcements_count} : 0;
        # prioritized_cve_announcements_count
        my $cve_count_prio= (defined $info->{prioritized_cve_announcements_count}) 
                            ? $info->{prioritized_cve_announcements_count} : 0;

        # Sum total CVEs
        $total_cves += $cve_count;

        # With or without CVE
        if ($cve_count > 0) {
            $assets_with_cve++;
        } else {
            $assets_no_cve++;
        }

        # With or without prioritized CVE
        if ($cve_count_prio > 0) {
            $assets_with_prioritized_cve++;
        } else {
            $assets_no_prioritized_cve++;
        }

        # Obsolete check => security_issues => sid == 'Obsolete-Os'
        if (defined($info->{security_issues}) && ref($info->{security_issues}) eq 'ARRAY') {
            foreach my $issue (@{$info->{security_issues}}) {
                if (defined($issue->{sid}) && $issue->{sid} eq 'Obsolete-Os') {
                    $assets_obsolete++;
                    last;  
                }
            }
        }

        # Reboot pending
        if (defined($info->{reboot_required}) && $info->{reboot_required}) {
            $assets_pending_reboot++;
        }
    }
    $assets_lost_communication = $custom_api->get_assets_communication_failed();

    # Build final message
    my $msg = sprintf(
        "Total: %d | Sans CVE: %d, Sans CVE prioritaire: %d, Avec CVE: %d, Avec CVE prioritaire: %d, Obsolètes: %d, Redémarrage nécessaire: %d, Pertes de communication: %d",
        $total_assets,
        $assets_no_cve,
        $assets_no_prioritized_cve,
        $assets_with_cve,
        $assets_with_prioritized_cve,
        $assets_obsolete,
        $assets_pending_reboot,
        $assets_lost_communication
    );

    # Check thresholds for total CVEs
    my $exit_cves = $self->{perfdata}->threshold_check(
        value => $assets_with_cve,
        threshold => [
            { label => 'critical-cves', exit_litteral => 'critical' },
            { label => 'warning-cves',  exit_litteral => 'warning' },
        ]
    );

    # Check thresholds for assets needing reboot
    my $exit_reboot = $self->{perfdata}->threshold_check(
        value => $assets_pending_reboot,
        threshold => [
            { label => 'critical-assets-need-reboot', exit_litteral => 'critical' },
            { label => 'warning-assets-need-reboot',  exit_litteral => 'warning' },
        ]
    );

    # Check thresholds for obsolete OS
    my $exit_obsolete = $self->{perfdata}->threshold_check(
        value => $assets_obsolete,
        threshold => [
            { label => 'critical-assets-obsolete', exit_litteral => 'critical' },
            { label => 'warning-assets-obsolete',  exit_litteral => 'warning' },
        ]
    );

    # Combine severities
    my $final_exit = $self->{output}->get_most_critical(
        status => [ $exit_cves, $exit_reboot, $exit_obsolete ]
    );

    # Add the final output with the worst severity
    $self->{output}->output_add(severity => $final_exit, short_msg => $msg);

    # Perfdata
    $self->{output}->perfdata_add(label => 'Total assets', value => $total_assets);
    $self->{output}->perfdata_add(label => 'Assets with no CVEs', value => $assets_no_cve);
    $self->{output}->perfdata_add(label => 'Assets with no prioritzed CVEs', value => $assets_no_prioritized_cve);
    $self->{output}->perfdata_add(label => 'Assets with CVEs', value => $assets_with_cve);
    $self->{output}->perfdata_add(label => 'Assets with prioritzed CVEs', value => $assets_with_prioritized_cve);
    $self->{output}->perfdata_add(label => 'Obsolete OS', value => $assets_obsolete);
    $self->{output}->perfdata_add(label => 'Need Reboot', value => $assets_pending_reboot);
    $self->{output}->perfdata_add(label => 'Assets lost communication', value => $assets_lost_communication);

    # Display final result
    $self->{output}->display();
    $self->{output}->exit();
}

1;

__END__

=head1 MODE

Fetches all assets, retrieves their details, and accumulates stats for CVEs, reboot-needed, and obsolete OS.
Applies thresholds on total CVEs, assets needing reboot, and assets obsolete if specified.

=over 8

=item B<--hostname>

Hostname or IP of the Cyberwatch server

=item B<--port>

Port (default: 443)

=item B<--api-username>

Basic auth username

=item B<--api-password>

Basic auth password

=item B<--warning-cves>

Warning threshold on the total number of CVEs

=item B<--critical-cves>

Critical threshold on the total number of CVEs

=item B<--warning-assets-need-reboot>

Warning threshold on the number of assets requiring a reboot

=item B<--critical-assets-need-reboot>

Critical threshold on the number of assets requiring a reboot

=item B<--warning-assets-obsolete>

Warning threshold on the number of obsolete OS assets

=item B<--critical-assets-obsolete>

Critical threshold on the number of obsolete OS assets

=back

=cut
