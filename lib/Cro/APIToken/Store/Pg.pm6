use Cro::APIToken::Store;
use DB::Pg;
use JSON::Fast;

class X::Cro::APIToken::Store::Pg::NoTable is Exception {
    has $.table-name;

    method message {
        "Could not find table with name '$!table-name'"
    }
}

class X::Cro::APIToken::Store::Pg::DangerousKey is Exception {
    has $.key;

    method message {
        "The key '$!key' is dangerous, suspecting an SQL injection";
    }
}

class Cro::APIToken::Store::Pg does Cro::APIToken::Store {
    has Str $.table-name = 'cro_api_tokens';
    has Bool $.create-table = True;
    has DB::Pg:D $.handle is required;

    submethod TWEAK {
         die X::Cro::APIToken::Store::Pg::NoTable.new(:$!table-name) unless self!check-db-table-presence;
    }

    method create-token(Str $token, DateTime $expiration, %metadata --> Nil) {
        $!handle.query("INSERT INTO $!table-name (token, expiration, metadata, revoked) VALUES (\$1, \$2, \$3, \$4)",
                $token, $expiration, %metadata, False);
    }

    method resolve-token(Cro::APIToken::Manager $manager, Str $token --> Cro::APIToken::Token) {
        my $res = $!handle.query("SELECT * FROM $!table-name WHERE token = \$1", $token).hash;
        with $res {
            Cro::APIToken::Token.new(:$manager, |$_);
        } else {
            return Cro::APIToken::Token;
        }
    }

    method find-tokens(Cro::APIToken::Manager $manager, :%metadata,
                       Bool :$expired = False, Bool :$revoked = True --> Seq) {
        my $ordered-keys = %metadata.keys.cache;
        for @$ordered-keys -> $key {
            die X::Cro::APIToken::Store::Pg::DangerousKey.new(:$key) unless $key ~~ /^<:L+[_-]>$/;
        }
        my $metadata-format = $ordered-keys.kv.map(-> $k, $v { "(metadata->>'$v') = \${ $k + 1 }" }).join(' AND ');
        $metadata-format = 'AND ' ~ $metadata-format if $metadata-format;

        my $query-text = "SELECT * FROM $!table-name WHERE { $expired ?? 'TRUE' !! 'expiration IS NULL OR expiration > now()::date' } { $revoked ?? '' !! 'AND revoked = FALSE' } " ~
                $metadata-format ~ ';';
        my $rows = $!handle.query($query-text, |$ordered-keys.map({ %metadata{$_} })).hashes;
        $rows.map({ Cro::APIToken::Token.new(:$manager, |$_) });
    }

    method revoke-token(Cro::APIToken::Token $token --> Nil) {
        $!handle.query("UPDATE $!table-name SET revoked = TRUE WHERE token = \$1;", $token.token);
    }

    method !check-db-table-presence() {
        my $table-exists = $!handle.query("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '$!table-name');").value;
        if !$table-exists && $!create-table {
            $!handle.execute("CREATE table $!table-name (id serial NOT NULL PRIMARY KEY, token text NOT NULL, expiration timestamp, metadata jsonb, revoked boolean);");
            return True;
        }
        $table-exists;
    }
}
