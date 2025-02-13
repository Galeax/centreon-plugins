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
        'hostname:s'                         => { name => 'hostname' },
        'port:s'                             => { name => 'port', default => 443 },
        'api-username:s'                     => { name => 'api_username' },
        'api-password:s'                     => { name => 'api_password' },
        'timeout:s'                          => { name => 'timeout', default => 60 },
        # Thresholds for total CVEs
        'warning-cves:s'                     => { name => 'warning_cves' },
        'critical-cves:s'                    => { name => 'critical_cves' },
        # Thresholds for assets needing reboot
        'warning-assets-need-reboot:s'         => { name => 'warning_assets_need_reboot' },
        'critical-assets-need-reboot:s'        => { name => 'critical_assets_need_reboot' },
        # Thresholds for obsolete OS
        'warning-assets-obsolete:s'            => { name => 'warning_assets_obsolete' },
        'critical-assets-obsolete:s'           => { name => 'critical_assets_obsolete' },
        # Thresholds for assets lost communication
        'warning-assets-lost-communication:s'  => { name => 'warning_assets_lost_communication' },
        'critical-assets-lost-communication:s' => { name => 'critical_assets_lost_communication' },
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
    # Assets lost communication
    $self->{perfdata}->threshold_validate(label => 'warning-assets-lost-communication',  value => $self->{option_results}->{warning_assets_lost_communication});
    $self->{perfdata}->threshold_validate(label => 'critical-assets-lost-communication', value => $self->{option_results}->{critical_assets_lost_communication});
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

        # cve_announcements_count (total CVEs)
        my $cve_count      = (defined $asset->{cve_announcements_count}) 
                             ? $asset->{cve_announcements_count} : 0;
        # prioritized_cve_announcements_count
        my $cve_count_prio = (defined $asset->{prioritized_cve_announcements_count}) 
                             ? $asset->{prioritized_cve_announcements_count} : 0;

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

        # Reboot pending
        if (defined($asset->{reboot_required}) && $asset->{reboot_required}) {
            $assets_pending_reboot++;
        }
    }
    
    $assets_lost_communication = $custom_api->get_assets_communication_failed();
    $assets_obsolete = $custom_api->get_obselete_os_count();

    # Build final message
    my $msg = sprintf(
        "Total: %d | No CVEs: %d, No prioritized CVEs: %d, With CVEs: %d, With prioritized CVEs: %d, Obsolete OS: %d, Reboot required: %d, Lost communication: %d",
        $total_assets,
        $assets_no_cve,
        $assets_no_prioritized_cve,
        $assets_with_cve,
        $assets_with_prioritized_cve,
        $assets_obsolete,
        $assets_pending_reboot,
        $assets_lost_communication
    );

    # Check thresholds for each metric
    my $exit_cves = $self->{perfdata}->threshold_check(
        value     => $assets_with_cve,
        threshold => [
            { label => 'critical-cves', exit_litteral => 'critical' },
            { label => 'warning-cves',  exit_litteral => 'warning' },
        ]
    );

    my $exit_reboot = $self->{perfdata}->threshold_check(
        value     => $assets_pending_reboot,
        threshold => [
            { label => 'critical-assets-need-reboot', exit_litteral => 'critical' },
            { label => 'warning-assets-need-reboot',  exit_litteral => 'warning' },
        ]
    );

    my $exit_obsolete = $self->{perfdata}->threshold_check(
        value     => $assets_obsolete,
        threshold => [
            { label => 'critical-assets-obsolete', exit_litteral => 'critical' },
            { label => 'warning-assets-obsolete',  exit_litteral => 'warning' },
        ]
    );

    my $exit_lost_comm = $self->{perfdata}->threshold_check(
        value     => $assets_lost_communication,
        threshold => [
            { label => 'critical-assets-lost-communication', exit_litteral => 'critical' },
            { label => 'warning-assets-lost-communication',  exit_litteral => 'warning' },
        ]
    );

    # Combine severities (each metric threshold directly affects the overall status)
    my $final_exit = $self->{output}->get_most_critical(
        status => [ $exit_cves, $exit_reboot, $exit_obsolete, $exit_lost_comm ]
    );

    # Add the final output with the worst severity
    $self->{output}->output_add(severity => $final_exit, short_msg => $msg);

    # Perfdata
    $self->{output}->perfdata_add(label => 'Total_assets',             value => $total_assets);
    $self->{output}->perfdata_add(label => 'No_CVEs',                  value => $assets_no_cve);
    $self->{output}->perfdata_add(label => 'No_prioritized_CVEs',      value => $assets_no_prioritized_cve);
    $self->{output}->perfdata_add(label => 'With_CVEs',                value => $assets_with_cve);
    $self->{output}->perfdata_add(label => 'With_prioritized_CVEs',    value => $assets_with_prioritized_cve);
    $self->{output}->perfdata_add(label => 'Obsolete_OS',              value => $assets_obsolete);
    $self->{output}->perfdata_add(label => 'Reboot_required',          value => $assets_pending_reboot);
    $self->{output}->perfdata_add(label => 'Lost_communication',       value => $assets_lost_communication);

    # Display final result
    $self->{output}->display();
    $self->{output}->exit();
}

1;

__END__

=head1 MODE

Fetches all assets, retrieves their details, and accumulates statistics for:
- Total CVEs
- Assets requiring reboot
- Obsolete OS assets
- Assets lost communication

Thresholds are applied on:
- Total CVEs (using --warning-cves and --critical-cves)
- Assets requiring reboot (using --warning-assets-need-reboot and --critical-assets-need-reboot)
- Obsolete OS assets (using --warning-assets-obsolete and --critical-assets-obsolete)
- Assets lost communication (using --warning-assets-lost-communication and --critical-assets-lost-communication)

A global timeout can be defined with the --timeout option (default: 60 seconds).

=over 8

=item B<--hostname>

Hostname or IP of the Cyberwatch server.

=item B<--port>

Port (default: 443).

=item B<--api-username>

Basic auth username.

=item B<--api-password>

Basic auth password.

=item B<--timeout>

Timeout in seconds for API requests (default: 60).

=item B<--warning-cves>

Warning threshold on the total number of assets with CVEs.

=item B<--critical-cves>

Critical threshold on the total number of assets with CVEs.

=item B<--warning-assets-need-reboot>

Warning threshold on the number of assets requiring a reboot.

=item B<--critical-assets-need-reboot>

Critical threshold on the number of assets requiring a reboot.

=item B<--warning-assets-obsolete>

Warning threshold on the number of assets with an obsolete OS.

=item B<--critical-assets-obsolete>

Critical threshold on the number of assets with an obsolete OS.

=item B<--warning-assets-lost-communication>

Warning threshold on the number of assets that lost communication.

=item B<--critical-assets-lost-communication>

Critical threshold on the number of assets that lost communication.

=back

=cut
