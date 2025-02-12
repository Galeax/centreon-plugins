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

package apps::cyberwatch::restapi::custom::api;

use strict;
use warnings;
use centreon::plugins::http;

sub new {
    my ($class, %options) = @_;
    my $self = {};
    bless $self, $class;

    if (!defined($options{output})) {
        print "Class custom: 'output' is required.\n";
        exit 3;
    }
    $self->{output} = $options{output};

    # Instantiate the Centreon HTTP helper
    $self->{http} = centreon::plugins::http->new(%options);

    return $self;
}

# Mandatory for classes used by 'script_custom'
sub set_defaults {
    my ($self, %options) = @_;
    return;  # No special defaults to set
}

sub check_options {
    my ($self, $options) = @_;
    return;
}

sub set_options {
    my ($self, %options) = @_;
    # We'll store the user’s CLI options here
    $self->{option_results} = $options{option_results};
}

sub ping {
    my ($self, %options) = @_;

    my $content = $self->{http}->request(
        method      => 'GET',
        proto       => 'https',
        hostname    => $self->{option_results}->{hostname},
        port        => $self->{option_results}->{port},
        url_path    => '/api/v3/ping',
        credentials => 1,
        insecure    => $self->{option_results}->{insecure},
        username    => $self->{option_results}->{api_username},
        password    => $self->{option_results}->{api_password},
        header      => [
            'Content-Type: application/json',
            'Accept: application/json',
        ],
    );

    if ($self->{http}->get_code() != 200) {
        $self->{output}->add_option_msg(
            short_msg => "HTTP error: " . $self->{http}->get_code() 
                         . " - " . $self->{http}->get_message()
        );
        $self->{output}->option_exit();
    }

    my $decoded;
    eval {
        require JSON;
        $decoded = JSON->new->utf8->decode($content);
    };
    if ($@) {
        $self->{output}->add_option_msg(short_msg => "Cannot decode JSON ping response: $@");
        $self->{output}->option_exit();
    }

    return $decoded;
}

sub get_assets {
    my ($self, %options) = @_;

    my $page = 1;
    my $previous_first_id;
    my @all_assets;

    while (1) {
        # Fetch one page
        my $content = $self->{http}->request(
            method      => 'GET',
            proto       => 'https',
            hostname    => $self->{option_results}->{hostname},
            port        => $self->{option_results}->{port},
            url_path    => '/api/v3/servers?page=' . $page,
            credentials => 1,
            insecure    => $self->{option_results}->{insecure},
            username    => $self->{option_results}->{api_username},
            password    => $self->{option_results}->{api_password},
            header      => [
                'Content-Type: application/json',
                'Accept: application/json',
            ],
        );

        if ($self->{http}->get_code() != 200) {
            $self->{output}->add_option_msg(
                short_msg => "HTTP error: " . $self->{http}->get_code()
                             . " - " . $self->{http}->get_message()
            );
            $self->{output}->option_exit();
        }

        my $decoded;
        eval {
            require JSON;
            $decoded = JSON->new->utf8->decode($content);
        };
        if ($@) {
            $self->{output}->add_option_msg(short_msg => "Cannot decode JSON (page=$page) : $@");
            $self->{output}->option_exit();
        }

        # Check if this page is empty
        if (ref($decoded) ne 'ARRAY' || scalar(@$decoded) == 0) {
            # No more assets, so break
            last;
        }

        # Compare first ID to see if we've already seen these assets
        my $current_first_id = $decoded->[0]->{id};
        if (defined($previous_first_id) && defined($current_first_id)) {
            if ($current_first_id eq $previous_first_id) {
                # The first element is the same as in the previous page => we’ve reached the end
                last;
            }
        }

        # Append these assets to the big list
        push @all_assets, @$decoded;

        # Store the new "previous" first ID, increment page
        $previous_first_id = $current_first_id;
        $page++;
    }

    return \@all_assets;
}

sub get_asset_security_info {
    my ($self, %options) = @_;
    
    # The asset_id is mandatory
    my $asset_id = $options{asset_id};
    if (!defined($asset_id)) {
        $self->{output}->add_option_msg(short_msg => "Missing 'asset_id' in get_asset_security_info.");
        $self->{output}->option_exit();
    }

    my $url_path = '/api/v3/vulnerabilities/servers/' . $asset_id . '';

    my $content = $self->{http}->request(
        method      => 'GET',
        proto       => 'https',
        hostname    => $self->{option_results}->{hostname},
        port        => $self->{option_results}->{port},
        url_path    => $url_path,
        credentials => 1,
        insecure    => $self->{option_results}->{insecure},
        username    => $self->{option_results}->{api_username},
        password    => $self->{option_results}->{api_password},
        header      => [
            'Content-Type: application/json',
            'Accept: application/json',
        ],
    );

    if ($self->{http}->get_code() != 200) {
        $self->{output}->add_option_msg(
            short_msg => "HTTP error getting security info for asset $asset_id: "
                         . $self->{http}->get_code() . " - "
                         . $self->{http}->get_message()
        );
        $self->{output}->option_exit();
    }

    my $decoded;
    eval {
        require JSON;
        $decoded = JSON->new->utf8->decode($content);
    };
    if ($@) {
        $self->{output}->add_option_msg(short_msg => "Cannot decode JSON security info for asset $asset_id: $@");
        $self->{output}->option_exit();
    }

    return $decoded;  
}

sub get_assets_communication_failed {
    my ($self, %options) = @_;

    my $page = 1;
    my $previous_first_id;
    my @all_assets;

    while (1) {
        my $content = $self->{http}->request(
            method      => 'GET',
            proto       => 'https',
            hostname    => $self->{option_results}->{hostname},
            port        => $self->{option_results}->{port},
            url_path    => '/api/v3/servers?communication_failed=true&page=' . $page,
            credentials => 1,
            insecure    => $self->{option_results}->{insecure},
            username    => $self->{option_results}->{api_username},
            password    => $self->{option_results}->{api_password},
            header      => [
                'Content-Type: application/json',
                'Accept: application/json',
            ],
        );

        if ($self->{http}->get_code() != 200) {
            $self->{output}->add_option_msg(
                short_msg => "HTTP error: " . $self->{http}->get_code()
                             . " - " . $self->{http}->get_message()
            );
            $self->{output}->option_exit();
        }

        my $decoded;
        eval {
            require JSON;
            $decoded = JSON->new->utf8->decode($content);
        };
        if ($@) {
            $self->{output}->add_option_msg(short_msg => "Cannot decode JSON (page=$page) : $@");
            $self->{output}->option_exit();
        }

        # If this page is empty => no more data
        if (ref($decoded) ne 'ARRAY' || scalar(@$decoded) == 0) {
            last;
        }

        # Compare first ID to detect loop
        my $current_first_id = $decoded->[0]->{id};
        if (defined($previous_first_id) && defined($current_first_id)) {
            if ($current_first_id eq $previous_first_id) {
                last;
            }
        }

        # Append the page data
        push @all_assets, @$decoded;

        $previous_first_id = $current_first_id;
        $page++;
    }

    # Return the total count of assets with communication failure
    return scalar(@all_assets);
}


1;

__END__

=head1 NAME

apps::cyberwatch::restapi::custom::api - Custom class for Cyberwatch REST API calls

=head1 SYNOPSIS

Manages Cyberwatch REST API calls (basic auth, endpoints, etc.).

=head1 METHODS

=head2 ping()

Calls C</api/v3/ping> to verify basic connectivity.

=head2 get_assets()

Calls C</api/v3/servers> to retrieve asset data (servers).

=head2 get_asset_security_info(asset_id)

Calls C</api/v3/vulnerabilities/servers/{asset_id}> to retrieve asset security data (servers).

=head2 get_assets_lost_communication()

Calls C</api/v3/servers?communication_failed=true> to retrieve numbers of assets that lost the connexion.


=cut
