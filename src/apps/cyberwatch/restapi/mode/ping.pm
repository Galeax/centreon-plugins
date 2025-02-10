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

package apps::cyberwatch::restapi::mode::ping;

use base qw(centreon::plugins::mode);
use strict;
use warnings;

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(%options);
    $self->{version} = '1.0';

    # Declare the CLI options
    $options{options}->add_options(arguments => {
        'hostname:s'     => { name => 'hostname' },
        'port:s'         => { name => 'port', default => 443 },
        'api-username:s' => { name => 'api_username' },
        'api-password:s' => { name => 'api_password' },
    });
    
    bless $self, $class;
    return $self;
}

# check_options is called automatically by the plugin engine
sub check_options {
    my ($self, %options) = @_;
    $self->SUPER::init(%options);

    # Ensure that required options are provided
    foreach my $param (qw(hostname api_username api_password)) {
        if (!defined($self->{option_results}->{$param}) || $self->{option_results}->{$param} eq '') {
            $self->{output}->add_option_msg(short_msg => "Need to specify --$param.");
            $self->{output}->option_exit();
        }
    }
}

sub run {
    my ($self, %options) = @_;

    # Retrieve the custom API object
    my $custom_api = $options{custom};

    # Pass our CLI options to the custom class
    $custom_api->set_options(option_results => $self->{option_results});

    # Call the ping method
    my $response = $custom_api->ping();

    # Check if there's a "uuid" field
    if (defined($response->{uuid})) {
        $self->{output}->output_add(
            severity  => 'OK',
            short_msg => "Ping successful - got uuid: $response->{uuid}"
        );
    } else {
        $self->{output}->output_add(
            severity  => 'CRITICAL',
            short_msg => "Ping failed or no 'uuid' field returned."
        );
    }

    # Print final output and exit
    $self->{output}->display();
    $self->{output}->exit();
}

1;

__END__

=head1 MODE

Test the Cyberwatch API connectivity using the /api/v3/ping endpoint.

=over 8

=item B<--hostname>

Hostname or IP of the Cyberwatch server (e.g. cyberwatch-demo.galeax.com)

=item B<--port>

Port (default: 443).

=item B<--api-username>

Basic auth username (from your Cyberwatch config).

=item B<--api-password>

Basic auth password (from your Cyberwatch config).

=back

=cut
